import jsonc
import logging

logger = logging.getLogger(__name__)

class Config(dict):
    """Configuration parser that loads JSON files into a dictionary."""

    def __init__(self, path: str = None):
        super().__init__()
        if path:
            self._load(path)

    # ------------------------------------------------------------------
    def _load(self, path: str) -> dict:
        """Load a JSON configuration file and update the dictionary with its contents.
        Args:
            path (str): The path to the JSON configuration file.
        Returns:
            dict: The updated dictionary with the contents of the JSON file.
        """
        data = None        
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        try:
            data = jsonc.loads(raw)
        except jsonc.JSONDecodeError:
            logger.error(f"sd;jfhbqsdkjfhgqsdkfjhgsdf")
            logger.error(f"Error parsing JSON configuration file: {path}")
            raise

        self.update(data)
        return data
