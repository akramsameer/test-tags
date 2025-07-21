"""
Box Scanner Strategy
--------------------------
Strategy for scanning files from Box.
"""

import json
import time
import traceback
from typing import Any, Dict, List, Tuple

from boxsdk.exception import BoxAPIException, BoxException


from jobs.reader.scanners.types import ScanResult
from jobs.reader.services.credential_service import CredentialService
from jobs.reader.utils.format_to_rfc3339 import format_to_rfc3339_box

from ..base_scanner_strategy import BaseScannerStrategy


class BoxStrategy(BaseScannerStrategy):
    """Box scanner strategy implementation."""

    # Constants for configuration
    MAX_BATCH_SIZE = 300  # Max files to process in one job run
    RATE_LIMIT_DELAY = 0.5  # Seconds to delay between API calls
    MAX_RETRIES = 3

    def __init__(self):
        """Initialize the Box scanner strategy."""
        self.processed_files_count = 0
        self.box_client = None
        self.current_offset = 0
        self.credential_service = CredentialService()
        self._api_error_occurred = False
        self.api_calls_count = 0
        self.api_errors_count = 0
        self.scan_started_at = None
        self.scan_completed_at = None
        self.last_scan_batch_at = None
        self.folder_paths = {}  # Cache for folder paths

    def scan(
        self, data_source: Dict[str, Any], scan_order: ScanOrderDict
    ) -> ScanResult:
        """
        Scan the Box data source and retrieve file metadata.

        Args:
            data_source (Dict[str, Any]): Data source configuration
            scan_order (ScanOrderDict): Scan order information
        Returns:
            ScanResult: A TypedDict containing:
                - files: List[FileMetadataDict] - List of file metadata
                - is_completed: bool - Whether the scan is complete
                - stats: ScanStats - Dictionary with scan statistics
                    - files_count: int - Number of files scanned in this batch
                    - last_scan_batch_at: float - Timestamp of the last scan batch
                    - scan_started_at: float - Timestamp of the scan start
                    - scan_completed_at: float - Timestamp of the scan completion
                    - api_calls_made: int - Number of API calls made
                    - api_errors_encountered: int - Number of API errors encountered
                - updated_credentials: Optional[Dict[str, Any]] - Updated OAuth credentials if any
                - error: Optional[str] - Error message if scan failed
        """
        source_id = data_source.get("id")
        logger.info(f"🔍 Scanning Box data source: {source_id}")

        # Reset counters for this job run
        self.processed_files_count = 0
        self.scan_started_at = time.time()
        self.scan_completed_at = None
        self.last_scan_batch_at = None

        try:
            # Authenticate with Box
            auth_result = self._authenticate(data_source)
            if not auth_result:
                return self.create_error_result(
                    "Failed to authenticate with Box", self.scan_started_at
                )

            self.box_client = auth_result["service"]
            updated_credentials = auth_result["updated_credentials"]

            if not self.box_client:
                return self.create_error_result(
                    "Failed to initialize Box client", self.scan_started_at
                )

            # Get scan cursor from scan order metadata
            cursor_data = scan_order.get("scan_metadata", {}).get("cursor", {})

            if cursor_data:
                self._restore_scan_state(cursor_data)
                logger.info(
                    f"📋 Resuming scan from cursor: processing folder {self.current_offset}"
                )
            else:
                self._initialize_scan_state(data_source)
                logger.info(
                    f"📋 Starting new scan for root folder: {self.current_offset}"
                )

            # Choose scan method based on scan type
            if scan_order.get("scan_type") == "incremental":
                logger.info("🔄 Starting incremental scan")
                result = self._incremental_scan(data_source, scan_order)
            else:
                logger.info("🔍 Starting full scan")
                result = self._full_scan(data_source, scan_order)

            # Update the result with the latest credentials if they were refreshed
            if updated_credentials:
                result["updated_credentials"] = updated_credentials

            return result

        except Exception as e:
            error_msg = f"Error scanning Box: {str(e)}"
            logger.error(error_msg)
            logger.error(f"📉 Traceback: {traceback.format_exc()}")
            if self.box_client:
                self._save_scan_state(scan_order)
            return self.create_error_result(error_msg, self.scan_started_at)

    def _build_folder_path(self, path_collection: Dict[str, Any]) -> str:
        """
        Build folder path from path_collection data.

        Args:
            path_collection: The path_collection data from Box API

        Returns:
            str: The folder path as a string
        """
        if not path_collection or not path_collection.get("entries"):
            return "/"

        # Extract folder names from path_collection entries
        # Skip the root folder (id: "0") if it's the first entry
        entries = path_collection.get("entries", [])
        folder_names = []

        for entry in entries:
            folder_id = entry.get("id")
            folder_name = entry.get("name")

            # Skip the root "All Files" folder if desired
            if folder_id == "0" and folder_name == "All Files":
                continue

            if folder_name:
                folder_names.append(folder_name)

        if not folder_names:
            return "/"

        # Join folder names with "/"
        return "/" + "/".join(folder_names)

    def _scan_folder_incremental(
        self, folder_id: str, modified_since: str, offset: int = 0, max_files: int = 100
    ) -> Tuple[List[FileMetadata], bool]:
        """
        Scan a Box folder for files modified or created since a specific timestamp.
        Uses Box's search API to get all files in the folder and its subfolders.

        Args:
            folder_id: The ID of the folder to scan
            modified_since: RFC 3339 timestamp to filter files by modification and creation time
            offset: The offset to start from for pagination
            max_files: Maximum number of files to retrieve

        Returns:
            Tuple of (files list, has_more flag)
        """
        logger.info(
            f"Scanning Box folder: {folder_id}, offset: {offset}, max_files: {max_files}"
        )
        logger.info(f"Modified since: {modified_since}")

        file_metadata_list = []
        has_more = False

        try:
            # Apply rate limiting
            time.sleep(self.RATE_LIMIT_DELAY)

            search_query = f"type:file ancestor_folder_ids:{folder_id} "

            # Get files using search API - make only one request without auto-iteration
            search_params = {
                "query": search_query,
                "updated_at_range": (modified_since, None),
                "type": "file",
                "limit": max_files,
                "offset": offset,
                "fields": "id,name,type,modified_at,created_at,size,shared_link,parent,path_collection",
            }

            # Execute a single request directly without letting the SDK auto-iterate
            response = self._execute_with_retry(
                lambda: self.box_client.make_request(
                    "GET", self.box_client.get_url("search"), params=search_params
                )
            )

            self.api_calls_count += 1

            # Log the raw response for debugging
            response_json = response.json() if response else {}

            if not response or not response_json.get("entries"):
                logger.info("No file results returned from API")
                return [], False

            # Get the JSON response
            items = response_json.get("entries", [])
            total_count = response_json.get("total_count", len(items))

            logger.info(
                f"Total count of modified/created files in folder {folder_id} and its subfolders: {total_count}"
            )
            logger.info(
                f"Search results - Total Count: {total_count}, Items returned: {len(items)}"
            )

            # Process files
            files_count = 0
            for item in items:
                # If we've reached the maximum files for this batch, stop processing
                if files_count >= max_files:
                    has_more = True
                    break

                try:
                    # Extract folder path from path_collection
                    folder_path = self._build_folder_path(
                        item.get("path_collection", {})
                    )

                    # Create file metadata with safe gets on all fields
                    file_metadata = FileMetadata(
                        id=item.get("id", f"unknown-{files_count}"),
                        name=item.get("name", f"unknown-{files_count}"),
                        source="box",
                        last_modified=item.get("modified_at"),
                        created_time=item.get("created_at"),
                        size=item.get("size", 0),
                        mime_type=self._get_mime_type_from_name(item.get("name", "")),
                        web_view_link=(
                            item.get("shared_link", {}).get("url", "")
                            if item.get("shared_link")
                            else ""
                        ),
                        parent_folder_id=item.get("parent", {}).get("id", folder_id),
                        folder_path=folder_path,
                    )

                    file_metadata_list.append(file_metadata)
                    files_count += 1
                except Exception as e:
                    logger.error(f"Error processing file: {str(e)}")
                    logger.error(f"Item data: {str(item)}")
                    self.api_errors_count += 1

            # Check if there are more results
            has_more = offset + len(file_metadata_list) < total_count

            # Log results
            logger.info(
                f"Found {len(file_metadata_list)} modified/created files in folder {folder_id} and its subfolders"
            )

            if has_more:
                logger.info("More results available")

            return file_metadata_list, has_more

        except Exception as e:
            error_msg = f"Error scanning Box folder {folder_id} for incremental changes: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            self._api_error_occurred = True
            raise e

    def _scan_folder(
        self, folder_id: str, offset: int = 0, max_files: int = 100
    ) -> Tuple[List[FileMetadata], bool]:
        """
        Scan a Box folder for files, including all files in subfolders.
        Uses Box's search API to get all files in the folder and its subfolders.

        Args:
            folder_id: The ID of the folder to scan
            offset: The offset to start from for pagination
            max_files: Maximum number of files to retrieve

        Returns:
            Tuple of (files list, has_more flag)
        """
        logger.info(
            f"Scanning Box folder: {folder_id}, offset: {offset}, max_files: {max_files}"
        )

        file_metadata_list = []
        has_more = False

        try:
            # Build search query for all files in this folder and its subfolders
            search_query = f"type:file ancestor_folder_ids:{folder_id}"
            logger.info(f"Search query: {search_query}")

            search_params = {
                "query": search_query,
                "type": "file",
                "limit": max_files,
                "offset": offset,
                "fields": "id,name,type,modified_at,created_at,size,shared_link,parent,path_collection",
            }

            # Apply rate limiting
            time.sleep(self.RATE_LIMIT_DELAY)

            # Get files using search API - only make one API call per batch
            response = self._execute_with_retry(
                lambda: self.box_client.make_request(
                    "GET", self.box_client.get_url("search"), params=search_params
                )
            )

            self.api_calls_count += 1

            response_json = response.json() if response else {}

            if not response_json or not response_json.get("entries"):
                logger.info(f"No files found in Box folder: {folder_id}")
                return [], False

            # Convert the collection to a list and get total count
            items = response_json.get("entries", [])
            total_count = response_json.get("total_count")

            logger.info(f"item.0: {json.dumps(items[0], indent=4)}")

            # Process files
            files_count = 0
            for item in items:
                # If we've reached the maximum files for this batch, stop processing
                if files_count >= max_files:
                    has_more = True
                    break

                try:
                    # Extract folder path from path_collection
                    folder_path = self._build_folder_path(
                        item.get("path_collection", {})
                    )

                    # Create file metadata
                    file_metadata = FileMetadata(
                        id=item.get("id"),
                        name=item.get("name"),
                        source="box",
                        last_modified=item.get("modified_at"),
                        created_time=item.get("created_at"),
                        size=item.get("size", 0),
                        mime_type=self._get_mime_type_from_name(item.get("name")),
                        web_view_link=(
                            item.get("shared_link", {}).get("url", "")
                            if item.get("shared_link")
                            else ""
                        ),
                        parent_folder_id=item.get("parent", {}).get("id", folder_id),
                        folder_path=folder_path,
                    )

                    file_metadata_list.append(file_metadata)
                    files_count += 1
                except Exception as e:
                    logger.error(f"Error processing file {item.get('id')}: {str(e)}")

            logger.info(
                f"------Total count of files in folder {folder_id} and its sub-folders ------: {total_count}"
            )

            # Check if there are more results
            if not has_more and offset + len(items) < total_count:
                has_more = True

            # Log results
            logger.info(
                f"Found {len(file_metadata_list)} files in folder {folder_id} and its subfolders"
            )
            if has_more:
                logger.info("More results available")

            return file_metadata_list, has_more

        except Exception as e:
            error_msg = f"Error scanning Box folder {folder_id}: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            self._api_error_occurred = True
            self.api_errors_count += 1
            raise e

    def _incremental_scan(
        self, data_source: Dict[str, Any], scan_order: ScanOrderDict
    ) -> ScanResult:
        """
        Perform an incremental scan of Box.
        Gets all files modified or created since the scanned_from timestamp.

        Args:
            data_source: Data source configuration
            scan_order: Scan order information

        Returns:
            ScanResult: A TypedDict containing:
                - files: List[FileMetadataDict] - List of file metadata
                - is_completed: bool - Whether the scan is complete
                - stats: ScanStats - Dictionary with scan statistics
                    - files_count: int - Number of files scanned in this batch
                    - last_scan_batch_at: float - Timestamp of the last scan batch
                    - scan_started_at: float - Timestamp of the scan start
                    - scan_completed_at: float - Timestamp of the scan completion
                    - api_calls_made: int - Number of API calls made
                    - api_errors_encountered: int - Number of API errors encountered
                - updated_credentials: Optional[Dict[str, Any]] - Updated OAuth credentials if any
                - error: Optional[str] - Error message if scan failed
        """
        datasource_id = data_source.get("id")
        logger.info(f"🔄 Incremental scan of Box data source: {datasource_id}")

        # Reset counters for this job run
        self.processed_files_count = 0
        self.scan_started_at = time.time()
        self.scan_completed_at = None
        self.last_scan_batch_at = None

        # Get the reference timestamp for incremental scan
        scan_from = scan_order.get("scanned_from")

        if not scan_from:
            scan_from = ScanOrderAdapter.get_last_completed_scan_timestamp(
                data_source.get("id")
            )
            if not scan_from:
                scan_from = "1970-01-01T00:00:00Z"
                logger.warning(
                    "⚠️ No reference timestamp specified for incremental scan, using default timestamp"
                )

        logger.info(f"🔄 Getting files modified since: {scan_from}")
        all_files = []
        updated_credentials = None

        try:
            # Format the timestamp for Box API
            scan_from_str = format_to_rfc3339_box(scan_from)

            # Get root folder ID from metadata or use "0" (Box root)
            metadata = data_source.get("metadata", {})
            root_folder_id = metadata.get("folder_id", "0")

            # Get cursor from scan order metadata
            cursor_data = scan_order.get("scan_metadata", {}).get("cursor", {})
            self.current_offset = cursor_data.get("current_offset", 0)

            # Scan the folder and its subfolders
            files, has_more = self._scan_folder_incremental(
                folder_id=root_folder_id,
                offset=self.current_offset,
                max_files=self.MAX_BATCH_SIZE,
                modified_since=scan_from_str.replace(".000Z", "Z"),
            )

            all_files.extend(files)
            self.processed_files_count += len(files)

            if has_more:
                self.current_offset += len(files)
            else:
                self.current_offset = 0

            # Save cursor
            self._save_scan_state(scan_order)

            # Check if scan is complete
            is_completed = not has_more

            # Convert to dictionaries
            file_dicts = [file.to_dict() for file in all_files]
            logger.info(f"✅ Processed {len(file_dicts)} modified files in this batch")

            result: ScanResult = {
                "files": file_dicts,
                "is_completed": is_completed,
                "stats": {
                    "files_count": len(file_dicts),
                    "last_scan_batch_at": time.time(),
                    "scan_started_at": self.scan_started_at,
                    "scan_completed_at": time.time(),
                    "api_calls_made": self.api_calls_count,
                    "api_errors_encountered": self.api_errors_count,
                },
                "updated_credentials": updated_credentials,
                "error": None,
            }

            return result

        except Exception as e:
            error_msg = f"Error in incremental scan of Box: {str(e)}"
            logger.error(error_msg)
            logger.error(f"📉 Traceback: {traceback.format_exc()}")
            if self.box_client:
                self._save_scan_state(scan_order)
            return self.create_error_result(error_msg, self.scan_started_at)

    def _full_scan(
        self, data_source: Dict[str, Any], scan_order: ScanOrderDict
    ) -> ScanResult:
        """
        Perform a full scan of Box.
        Gets all files in the specified folder and its subfolders.

        Args:
            data_source: Data source configuration
            scan_order: Scan order information

        Returns:
            ScanResult: A TypedDict containing:
                - files: List[FileMetadataDict] - List of file metadata
                - is_completed: bool - Whether the scan is complete
                - stats: ScanStats - Dictionary with scan statistics
                    - files_count: int - Number of files scanned in this batch
                    - last_scan_batch_at: float - Timestamp of the last scan batch
                    - scan_started_at: float - Timestamp of the scan start
                    - scan_completed_at: float - Timestamp of the scan completion
                    - api_calls_made: int - Number of API calls made
                    - api_errors_encountered: int - Number of API errors encountered
                - updated_credentials: Optional[Dict[str, Any]] - Updated OAuth credentials if any
                - error: Optional[str] - Error message if scan failed
        """
        datasource_id = data_source.get("id")
        logger.info(f"🔍 Full scan of Box data source: {datasource_id}")

        # Reset counters for this job run
        self.processed_files_count = 0
        self.scan_started_at = time.time()
        self.scan_completed_at = None
        self.last_scan_batch_at = None

        all_files = []
        updated_credentials = None

        try:
            # Get root folder ID from metadata or use "0" (Box root)
            metadata = data_source.get("metadata", {})
            root_folder_id = metadata.get("folder_id", "0")

            # Get cursor from scan order metadata
            cursor_data = scan_order.get("scan_metadata", {}).get("cursor", {})
            self.current_offset = cursor_data.get("current_offset", 0)

            # Scan the folder and its subfolders
            files, has_more = self._scan_folder(
                folder_id=root_folder_id,
                offset=self.current_offset,
                max_files=self.MAX_BATCH_SIZE,
            )

            all_files.extend(files)
            self.processed_files_count += len(files)

            if has_more:
                self.current_offset += len(files)
            else:
                self.current_offset = 0

            # Save cursor
            self._save_scan_state(scan_order)

            # Check if scan is complete
            is_completed = not has_more

            # Convert to dictionaries
            file_dicts = [file.to_dict() for file in all_files]
            logger.info(f"✅ Processed {len(file_dicts)} files in this batch")

            result: ScanResult = {
                "files": file_dicts,
                "is_completed": is_completed,
                "stats": {
                    "files_count": len(file_dicts),
                    "last_scan_batch_at": time.time(),
                    "scan_started_at": self.scan_started_at,
                    "scan_completed_at": time.time(),
                    "api_calls_made": self.api_calls_count,
                    "api_errors_encountered": self.api_errors_count,
                },
                "updated_credentials": updated_credentials,
                "error": None,
            }

            return result

        except Exception as e:
            error_msg = f"Error in full scan of Box: {str(e)}"
            logger.error(error_msg)
            logger.error(f"📉 Traceback: {traceback.format_exc()}")
            if self.box_client:
                self._save_scan_state(scan_order)
            return self.create_error_result(error_msg, self.scan_started_at)

    def _save_scan_state(self, scan_order: ScanOrderDict) -> None:
        """
        Save current scan state as a cursor.

        Args:
            scan_order: The scan order to update
        """
        cursor_data = {
            "current_offset": self.current_offset,
            "last_updated": time.time(),
        }

        # Update scan metadata with cursor data
        scan_metadata = scan_order.get("scan_metadata", {})
        scan_metadata["cursor"] = cursor_data
        scan_order["scan_metadata"] = scan_metadata

        # Persist the changes to the database
        ScanOrderAdapter.update_scan_metadata(scan_order["id"], {"cursor": cursor_data})

    def _authenticate(self, data_source: Dict[str, Any]) -> Any:
        """
        Authenticate with Box using the appropriate authentication strategy.

        Args:
            data_source: The data source containing authentication information

        Returns:
            The authenticated Box client or None if authentication fails,
            or a dictionary with the client and updated credentials if tokens were refreshed
        """
        # Get the appropriate auth handler based on auth_type
        auth_type = data_source.get("auth_type", "oauth")

        if not auth_type:
            logger.error("❌ Missing auth_type in data source configuration")
            return None

        logger.debug(f"🔐 Using auth type: {auth_type} for Box scanning")
        auth_handler = BoxAuthFactory.get_auth_handler(auth_type)

        if not auth_handler:
            logger.error(f"❌ Unsupported auth type for Box: {auth_type}")
            return None

        return auth_handler.authenticate(data_source)

    def create_error_result(self, error_msg: str, scan_started_at: float) -> ScanResult:
        """
        Create a scan result object for error cases.

        Args:
            error_msg: The error message
            scan_started_at: The timestamp when the scan started

        Returns:
            ScanResult: A result object indicating the error
        """
        return {
            "files": [],
            "is_completed": False,
            "stats": {
                "files_count": 0,
                "last_scan_batch_at": time.time(),
                "scan_started_at": scan_started_at,
                "scan_completed_at": None,
                "api_calls_made": self.api_calls_count,
                "api_errors_encountered": self.api_errors_count,
            },
            "updated_credentials": None,
            "error": error_msg,
        }

    def _get_mime_type_from_name(self, filename: str) -> str:
        """
        Determine MIME type from filename extension.

        Args:
            filename: The name of the file

        Returns:
            str: The MIME type
        """
        if not filename:
            return "application/octet-stream"

        # Extract extension from name
        name_parts = filename.split(".")
        if len(name_parts) > 1:
            ext = name_parts[-1].lower()

            # Map common extensions to MIME types
            extension_to_mime = {
                "pdf": "application/pdf",
                "doc": "application/msword",
                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "xls": "application/vnd.ms-excel",
                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "ppt": "application/vnd.ms-powerpoint",
                "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "txt": "text/plain",
                "csv": "text/csv",
                "jpg": "image/jpeg",
                "jpeg": "image/jpeg",
                "png": "image/png",
                "gif": "image/gif",
                "html": "text/html",
                "htm": "text/html",
                "json": "application/json",
                "xml": "application/xml",
                "zip": "application/zip",
            }

            return extension_to_mime.get(ext, f"application/{ext}")

        return "application/octet-stream"

    def _initialize_scan_state(self, data_source: Dict[str, Any]) -> None:
        """
        Initialize scan state for a new scan.

        Args:
            data_source: The data source to scan
        """
        # Get root folder ID from metadata or use "0" (Box root)
        metadata = data_source.get("metadata", {})
        root_folder_id = metadata.get("folder_id")

        if not root_folder_id:
            logger.warning(
                "⚠️ No folder ID specified in data source metadata, scanning root folder"
            )
            root_folder_id = "0"  # Box uses "0" as the root folder ID

        # Initialize the scanner state
        self.current_offset = 0

    def _restore_scan_state(self, cursor_data: Dict[str, Any]) -> None:
        """
        Restore scan state from a cursor.

        Args:
            cursor_data: The cursor data to restore from
        """
        self.current_offset = cursor_data.get("current_offset", 0)

    def _execute_with_retry(self, api_request_func, **kwargs):
        """
        Execute a Box API request with exponential backoff retry logic.

        Args:
            api_request_func: The API request function to execute
            **kwargs: Arguments to pass to the API request function

        Returns:
            The API response or None if all retries fail
        """
        for retry in range(self.MAX_RETRIES + 1):
            try:
                if retry > 0:
                    # Exponential backoff for retries
                    delay = self.RETRY_DELAY * (2 ** (retry - 1))
                    logger.warning(
                        f"Retrying API request (attempt {retry}/{self.MAX_RETRIES}) after {delay}s delay"
                    )
                    time.sleep(delay)

                # Execute the API request
                return api_request_func(**kwargs)

            except BoxAPIException as e:
                status_code = e.status

                # Handle rate limiting (429) or server errors (5xx)
                if status_code == 429 or 500 <= status_code < 600:
                    if retry == self.MAX_RETRIES:
                        logger.error(
                            f"API request failed after {self.MAX_RETRIES} retries: {str(e)}"
                        )
                        raise e
                    else:
                        logger.warning(
                            f"API request hit rate limit or server error (status: {status_code}), will retry"
                        )
                        continue
                elif status_code == 404:
                    # Handle not found errors
                    logger.error(f"Resource not found (404): {str(e)}")
                    raise e
                elif status_code == 403:
                    # Handle permission errors
                    logger.error(f"Permission denied (403): {str(e)}")
                    raise e
                else:
                    # Handle other HTTP errors
                    logger.error(
                        f"API request failed with status {status_code}: {str(e)}"
                    )
                    raise e
            except BoxException as e:
                # Handle other Box errors
                logger.error(f"Box API error: {str(e)}")
                if retry == self.MAX_RETRIES:
                    logger.error(f"API request failed after {self.MAX_RETRIES} retries")
                    raise e
            except Exception as e:
                # Handle unexpected errors
                logger.error(f"Unexpected error in API request: {str(e)}")
                if retry == self.MAX_RETRIES:
                    logger.error(f"API request failed after {self.MAX_RETRIES} retries")
                    raise e
