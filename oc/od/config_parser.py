"""
config_parser.py – remplacement de cherrypy.lib.reprconf.Config

Lit les fichiers de configuration au format CherryPy/INI :
  [global]
  key : 'python literal value'
  key2 : { 'nested': True }

Les valeurs sont des littéraux Python évalués via ast.literal_eval.
"""

import ast
import configparser
import logging

logger = logging.getLogger(__name__)


class Config(dict):
    """Remplace cherrypy.lib.reprconf.Config.

    Lit un fichier .config au format INI avec des valeurs Python littérales.
    Retourne un dict dont les clés sont les noms de sections et dont les
    valeurs sont des dict des clés/valeurs de chaque section.
    Les clés hors section sont stockées à la racine du dict.
    """

    def __init__(self, path: str = None):
        super().__init__()
        if path:
            self._load(path)

    # ------------------------------------------------------------------
    def _load(self, path: str) -> None:
        parser = configparser.RawConfigParser(
            delimiters=(":", "="),
            comment_prefixes=("#", ";"),
            inline_comment_prefixes=("#",),
            strict=False,
        )
        parser.optionxform = str  # préserve la casse des clés

        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()

        # ConfigParser exige au moins une section ; si le fichier n'en a pas,
        # on en crée une section virtuelle.
        if not any(line.strip().startswith("[") for line in raw.splitlines()):
            raw = "[__root__]\n" + raw

        parser.read_string(raw)

        for section in parser.sections():
            section_dict: dict = {}
            for key, value in parser.items(section, raw=True):
                section_dict[key] = self._parse_value(value)
            if section == "__root__":
                self.update(section_dict)
            else:
                self[section] = section_dict

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_value(value: str):
        """Évalue la valeur comme un littéral Python si possible.

        Applique d'abord le dés-échappement %% → % identique au comportement
        de configparser.BasicInterpolation (utilisé par CherryPy reprconf), afin
        que les chaînes de format de logging comme '%%(asctime)s' soient lues
        correctement comme '%(asctime)s'.
        """
        if value is None:
            return None
        value = value.strip()
        if not value:
            return value
        # Unescape %% → % to match legacy CherryPy configparser.BasicInterpolation
        value = value.replace("%%", "%")
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
