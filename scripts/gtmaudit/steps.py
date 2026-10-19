"""GTM interface wording, in English or French: object labels, readable types, and one step per action.

Every analyst-facing name of a GTM object, field or value comes from here. Values pass through the privacy
projection first; a field without a known interface label is named by its exported key.
"""

from __future__ import annotations

import copy
import json
import re

from .paths import segments
from .privacy import mask_action, redact
from .source import CODE_FIELDS, SYSTEM_TRIGGER_NAMES, Model, conditions

LAYERS = {"tag": ("Tag", "Balise"), "trigger": ("Trigger", "Déclencheur"), "variable": ("Variable", "Variable"),
          "template": ("Template", "Modèle"), "folder": ("Folder", "Dossier"), "zone": ("Zone", "Zone"),
          "container": ("Container", "Conteneur")}

TYPES = {
    "googtag": ("Google tag", "Balise Google"), "gaawe": ("GA4 event", "Événement GA4"),
    "gaawc": ("GA4 configuration (legacy)", "Configuration GA4 (ancienne)"), "ua": ("Universal Analytics", "Universal Analytics"),
    "awct": ("Google Ads conversion tracking", "Suivi des conversions Google Ads"),
    "sp": ("Google Ads remarketing", "Remarketing Google Ads"), "gclidw": ("Conversion Linker", "Linker de conversion"),
    "awcc": ("Google Ads calls from website", "Appels depuis le site Google Ads"),
    "awud": ("Google Ads user-provided data event", "Événement de données fournies par l'utilisateur Google Ads"),
    "flc": ("Floodlight counter", "Compteur Floodlight"), "fls": ("Floodlight sales", "Ventes Floodlight"),
    "html": ("Custom HTML", "HTML personnalisé"), "img": ("Custom image", "Image personnalisée"),
    "PAGEVIEW": ("Page View", "Page vue"), "DOM_READY": ("DOM Ready", "DOM prêt"),
    "WINDOW_LOADED": ("Window Loaded", "Fenêtre chargée"), "CUSTOM_EVENT": ("Custom Event", "Événement personnalisé"),
    "CLICK": ("Click - All Elements", "Clic - Tous les éléments"), "LINK_CLICK": ("Click - Just Links", "Clic - Liens uniquement"),
    "FORM_SUBMISSION": ("Form Submission", "Envoi de formulaire"), "TIMER": ("Timer", "Minuteur"),
    "SCROLL_DEPTH": ("Scroll Depth", "Profondeur de défilement"),
    "ELEMENT_VISIBILITY": ("Element Visibility", "Visibilité de l'élément"),
    "TRIGGER_GROUP": ("Trigger Group", "Groupe de déclencheurs"), "HISTORY_CHANGE": ("History Change", "Changement d'historique"),
    "JS_ERROR": ("JavaScript Error", "Erreur JavaScript"), "YOU_TUBE_VIDEO": ("YouTube Video", "Vidéo YouTube"),
    "CONSENT_INIT": ("Consent Initialization", "Initialisation du consentement"), "INIT": ("Initialization", "Initialisation"),
    "v": ("Data Layer Variable", "Variable de couche de données"), "c": ("Constant", "Constante"),
    "k": ("1st-Party Cookie", "Cookie propriétaire"), "j": ("JavaScript Variable", "Variable JavaScript"),
    "jsm": ("Custom JavaScript", "JavaScript personnalisé"), "u": ("URL", "URL"), "d": ("DOM Element", "Élément DOM"),
    "smm": ("Lookup Table", "Table de correspondance"), "remm": ("RegEx Table", "Table d'expressions régulières"),
    "gtes": ("Google tag: Event Settings", "Balise Google : paramètres d'événement"),
    "gtcs": ("Google tag: Configuration Settings", "Balise Google : paramètres de configuration"),
    "awec": ("User-Provided Data", "Données fournies par l'utilisateur"), "f": ("HTTP Referrer", "URL de provenance HTTP"),
    "e": ("Custom Event", "Événement personnalisé"), "aev": ("Auto-Event Variable", "Variable d'événement automatique"),
    "r": ("Random Number", "Nombre aléatoire"), "vis": ("Element Visibility", "Visibilité de l'élément"),
    "cid": ("Container ID", "ID du conteneur"), "dbg": ("Debug Mode", "Mode débogage"),
    "gas": ("Google Analytics Settings (Universal Analytics)", "Paramètres Google Analytics (Universal Analytics)"),
    "baut": ("Microsoft Advertising UET", "Microsoft Advertising UET"), "pntr": ("Pinterest Tag", "Balise Pinterest"),
    "crto": ("Criteo OneTag", "Criteo OneTag"), "bzi": ("LinkedIn Insight", "LinkedIn Insight"),
    "abtGeneric": ("AB Tasty", "AB Tasty"),
}

# GTM labels of every source.OBJECT_FIELDS key; parameter keys (PARAMS) can also be data names.
FIELDS = {
    "firingTriggerId": ("Triggering", "Déclenchement"),
    "blockingTriggerId": ("Triggering › Exceptions", "Déclenchement › Exceptions"),
    "tagFiringOption": ("Advanced settings › Tag firing options",
                        "Paramètres avancés › Options de déclenchement de la balise"),
    "priority": ("Advanced settings › Tag firing priority", "Paramètres avancés › Priorité de déclenchement"),
    "consentSettings": ("Advanced settings › Consent settings", "Paramètres avancés › Paramètres de consentement"),
    "setupTag": ("Advanced settings › Tag sequencing › Fire a tag before",
                 "Paramètres avancés › Ordre des balises › Déclencher une balise avant"),
    "teardownTag": ("Advanced settings › Tag sequencing › Fire a tag after",
                    "Paramètres avancés › Ordre des balises › Déclencher une balise après"),
    "parentFolderId": ("Folder", "Dossier"), "notes": ("Notes", "Notes"), "type": ("Type", "Type"),
    "customEventFilter": ("Event name", "Nom de l'événement"),
    "filter": ("This trigger fires on › Some events", "Ce déclencheur se déclenche sur › Certains événements"),
    "autoEventFilter": ("Enable this trigger when", "Activer ce déclencheur lorsque"),
    "templateData": ("Template file", "Fichier du modèle"),
    "waitForTags": ("Wait for tags", "Attendre les balises"), "waitForTagsTimeout": ("Max wait time", "Délai maximal"),
    "checkValidation": ("Check validation", "Vérifier la validation"),
}
PARAMS = {
    "eventName": ("Event name", "Nom de l'événement"), "eventSettingsTable": ("Event parameters", "Paramètres d'événement"),
    "eventSettingsVariable": ("Event settings variable", "Variable de paramètres d'événement"),
    "configSettingsTable": ("Configuration settings", "Paramètres de configuration"),
    "configSettingsVariable": ("Configuration settings variable", "Variable de paramètres de configuration"),
    "userProperties": ("User properties", "Propriétés utilisateur"), "html": ("HTML", "HTML"),
    "javascript": ("Custom JavaScript", "JavaScript personnalisé"),
    "measurementIdOverride": ("Measurement ID", "ID de mesure"), "measurementId": ("Measurement ID", "ID de mesure"),
    "tagId": ("Tag ID", "ID de balise"), "conversionId": ("Conversion ID", "ID de conversion"),
    "conversionLabel": ("Conversion label", "Libellé de conversion"),
    "conversionValue": ("Conversion value", "Valeur de conversion"), "currencyCode": ("Currency code", "Code de devise"),
    "orderId": ("Transaction ID", "ID de transaction"),
    "supportDocumentWrite": ("Support document.write", "Prise en charge de document.write"),
    "map": ("Lookup table", "Table de correspondance"), "input": ("Input variable", "Variable d'entrée"),
    "defaultValue": ("Default value", "Valeur par défaut"), "setDefaultValue": ("Set default value", "Définir une valeur par défaut"),
    "name": ("Name", "Nom"), "value": ("Value", "Valeur"), "triggerIds": ("Triggers", "Déclencheurs"),
    "dataLayerVersion": ("Data Layer Version", "Version de la couche de données"),
    "sendEcommerceData": ("Send Ecommerce data", "Envoyer les données d'e-commerce"),
}
GENERATED = {"uniqueTriggerId", "fingerprint", "tagManagerUrl", "accountId", "containerId", "path"}

ENTRIES = {"parameter": ("parameter name", "nom du paramètre"), "parameterValue": ("value", "valeur"),
           "key": ("input", "entrée"), "value": ("value", "valeur"), "name": ("name", "nom"),
           "arg0": ("variable", "variable"), "arg1": ("value", "valeur"), "type": ("operator", "opérateur")}

ENUMS = {
    "ONCE_PER_EVENT": ("Once per event", "Une fois par événement"), "ONCE_PER_LOAD": ("Once per page", "Une fois par page"),
    "UNLIMITED": ("Unlimited", "Illimité"),
    "EQUALS": ("equals", "est égal à"), "CONTAINS": ("contains", "contient"), "STARTS_WITH": ("starts with", "commence par"),
    "ENDS_WITH": ("ends with", "se termine par"), "MATCH_REGEX": ("matches RegEx", "correspond à l'expression régulière"),
    "CSS_SELECTOR": ("matches CSS selector", "correspond au sélecteur CSS"), "LESS": ("less than", "inférieur à"),
    "GREATER": ("greater than", "supérieur à"), "LESS_OR_EQUALS": ("less than or equal to", "inférieur ou égal à"),
    "GREATER_OR_EQUALS": ("greater than or equal to", "supérieur ou égal à"),
}
NEGATED = {
    "EQUALS": ("does not equal", "n'est pas égal à"), "CONTAINS": ("does not contain", "ne contient pas"),
    "STARTS_WITH": ("does not start with", "ne commence pas par"), "ENDS_WITH": ("does not end with", "ne se termine pas par"),
    "MATCH_REGEX": ("does not match RegEx", "ne correspond pas à l'expression régulière"),
    "CSS_SELECTOR": ("does not match CSS selector", "ne correspond pas au sélecteur CSS"),
}

WORDS = {
    "en": {"set": "{obj}: set {field} to {value}", "add": "{obj}: in {field}, add {value}",
           "remove": "{obj}: remove {field}", "create": "Create {layer} \"{name}\" ({type})",
           "delete": "Delete {obj}", "pause": "Pause {obj}", "unpause": "Unpause {obj}",
           "rename": "Rename {obj} to \"{name}\"", "remap": "Replace {src} with {dst} everywhere it is used: {users}",
           "set_many": "Set {field} to {value} on these {n} objects:",
           "add_many": "In {field}, add {value} on these {n} objects:",
           "remove_many": "Remove {field} from these {n} objects:", "delete_many": "Delete these {n} objects:",
           "pause_many": "Pause these {n} objects:", "unpause_many": "Unpause these {n} objects:",
           "nowhere": "nothing uses it today", "row": "row", "condition": "condition", "item": "item",
           "case": "ignore case", "regex": "use regex matching",
           "consent_none": "No additional consent required", "consent_unset": "Not set",
           "consent_needed": "Require additional consent for tag to fire: {types}",
           "stop": "don't fire if the other tag fails", "yes": "yes", "no": "no", "empty": "(empty)"},
    "fr": {"set": "{obj} : définir {field} sur {value}", "add": "{obj} : dans {field}, ajouter {value}",
           "remove": "{obj} : supprimer {field}", "create": "Créer {layer} « {name} » ({type})",
           "delete": "Supprimer {obj}", "pause": "Mettre en pause {obj}", "unpause": "Réactiver {obj}",
           "rename": "Renommer {obj} en « {name} »",
           "remap": "Remplacer {src} par {dst} partout où il est utilisé : {users}",
           "set_many": "Définir {field} sur {value} pour ces {n} objets :",
           "add_many": "Dans {field}, ajouter {value} pour ces {n} objets :",
           "remove_many": "Supprimer {field} de ces {n} objets :", "delete_many": "Supprimer ces {n} objets :",
           "pause_many": "Mettre en pause ces {n} objets :", "unpause_many": "Réactiver ces {n} objets :",
           "nowhere": "rien ne l'utilise aujourd'hui", "row": "ligne", "condition": "condition", "item": "élément",
           "case": "ignorer la casse",
           "regex": "utiliser la correspondance d'expression régulière",
           "consent_none": "Aucun consentement supplémentaire requis", "consent_unset": "Non défini",
           "consent_needed": "Exiger un consentement supplémentaire pour déclencher la balise : {types}",
           "stop": "ne pas déclencher si l'autre balise échoue", "yes": "oui", "no": "non", "empty": "(vide)"},
}
WRITES = ("set", "add", "remove")
STATE = ("delete", "pause", "unpause")
KEY_RE = re.compile(r"new:(?:tag|trigger|variable|folder):[\w-]+|\b(?:tag|trigger|variable|template|folder|zone):\d+\b")


class Interface:
    """Analyst-facing names for one audit: source objects plus objects the operations create."""

    def __init__(self, model: Model, operations: list[dict], lang: str):
        self.model, self.lang, self.i = model, lang, 1 if lang == "fr" else 0
        self.words = WORDS[lang]
        self.current: dict[str, str] = {}  # names in the state being described; empty means the source
        self.created: dict[str, tuple[str, dict]] = {}
        for op in operations:
            for a in op["actions"]:
                if a["do"] == "create":
                    self.created[a["ref"]] = (a["layer"], a["object"])

    def pick(self, pair: tuple[str, str]) -> str:
        return pair[self.i]

    def name(self, key: str) -> str:
        if key in self.current:
            return self.current[key]
        if key in self.created:
            return str(self.created[key][1].get("name", key))
        if key.startswith("trigger:") and key[8:] in SYSTEM_TRIGGER_NAMES:
            return SYSTEM_TRIGGER_NAMES[key[8:]]
        obj = self.model.get(key)
        return obj.name if obj else key

    def named(self, layer: str, name: str) -> str:
        """Tag "GA4 - purchase" (French: Balise « GA4 - purchase »)."""
        word = self.pick(LAYERS.get(layer, (layer, layer)))
        return f"{word} « {name} »" if self.lang == "fr" else f"{word} \"{name}\""

    def label(self, key: str) -> str:
        if key == "container":
            return self.pick(LAYERS["container"])
        return self.named(key.split(":")[1] if key.startswith("new:") else key.split(":")[0], self.name(key))

    def cite(self, text: str) -> str:
        """Prose with every cited object key shown as its label."""
        def repl(m: re.Match) -> str:
            key = m.group(0)
            return self.label(key) if key in self.created or key in self.model.objects or \
                (key.startswith("trigger:") and key[8:] in SYSTEM_TRIGGER_NAMES) else key
        return redact(KEY_RE.sub(repl, text or ""))

    def type_name(self, layer: str, kind: str) -> str:
        if kind.startswith("cvt_"):
            template = self.model.get(f"template:{kind.rsplit('_', 1)[-1]}")
            return f"{self.pick(LAYERS['template'])}: {template.name}" if template else kind
        if layer in ("folder", "template", "zone"):
            return self.pick(LAYERS[layer])
        return self.pick(TYPES[kind]) if kind in TYPES else kind

    # ---------- fields and values ----------

    def field(self, path: str) -> str:
        parts, family = [], ""
        for seg in segments(path):
            if seg in ("list", "value"):
                continue
            if seg.startswith("parameter:"):
                key = seg[10:]
                parts.append(self.pick(ENTRIES[key]) if family and key in ENTRIES else
                             self.pick(PARAMS[key]) if key in PARAMS else f"\"{key}\"")
            elif seg.startswith("map:"):
                key = seg[4:]
                parts.append(self.pick(ENTRIES[key]) if key in ENTRIES else f"\"{key}\"")
            elif seg.startswith("row:"):
                parts.append(f"{self.words['row']} \"{seg[4:].partition('=')[2]}\"")
            elif seg.startswith("["):
                n = int(seg[1:-1]) + 1
                parts.append(f"{self.words['condition' if family else 'item']} {n}")
            elif family and seg in ENTRIES:
                parts.append(self.pick(ENTRIES[seg]))
            else:
                family = seg if seg in ("filter", "customEventFilter", "autoEventFilter") else family
                parts.append(self.pick(FIELDS[seg]) if seg in FIELDS else f"\"{seg}\"")
        return " › ".join(parts)

    def trigger_names(self, value) -> str:
        ids = value if isinstance(value, list) else [value]
        return ", ".join(f"\"{self.name(i if str(i).startswith('new:') else f'trigger:{i}')}\"" for i in ids)

    def _conditions(self, value: list, event_name: bool = False) -> list[str]:
        """Trigger conditions as GTM shows them; a Custom Event trigger's {{_event}} condition is its Event name."""
        out = []
        for c in conditions({"filter": value}):
            if c["negate"]:
                plain = self.pick(ENUMS.get(c["op"], (c["op"], c["op"])))
                op = self.pick(NEGATED.get(c["op"], (f"not {plain}", f"non {plain}")))
            else:
                op = self.pick(ENUMS.get(c["op"], (c["op"], c["op"])))
            case = f" ({self.words['case']})" if c["ignore_case"] else ""
            if event_name and c["arg0"] == "{{_event}}" and not c["negate"] and c["op"] in ("EQUALS", "MATCH_REGEX"):
                regex = f" ({self.words['regex']})" if c["op"] == "MATCH_REGEX" else ""
                out.append(f"\"{c['arg1']}\"{regex}{case}")
            else:
                out.append(f"{c['arg0']} {op} \"{c['arg1']}\"{case}")
        return out

    def _row(self, row: dict) -> str:
        entries = {m.get("key"): m.get("value", json.dumps(m.get("list", ""), ensure_ascii=False))
                   for m in row.get("map", []) or [] if isinstance(m, dict)}
        if "parameter" in entries:
            return f"\"{entries['parameter']}\" = {entries.get('parameterValue', '')}"
        if "key" in entries and "value" in entries:
            return f"{entries['key']} → {entries['value']}"
        return ", ".join(f"{k}: {v}" for k, v in entries.items())

    def value(self, field: str, value, code: str = "") -> list[str]:
        """Readable value lines for one field (already masked). `code` names where the new code or file is."""
        if code:
            return [code]
        if field in ("firingTriggerId", "blockingTriggerId"):
            return [self.trigger_names(value)] if value not in (None, [], "") else [self.words["empty"]]
        if field in ("filter", "customEventFilter", "autoEventFilter") and isinstance(value, list):
            return self._conditions(value, field == "customEventFilter") or [self.words["empty"]]
        if field == "consentSettings" and isinstance(value, dict):
            status = value.get("consentStatus")
            if status == "NEEDED":
                types = [str(t.get("value")) for t in (value.get("consentType") or {}).get("list", []) or []]
                return [self.words["consent_needed"].format(types=", ".join(types))]
            return [self.words["consent_none" if status == "NOT_NEEDED" else "consent_unset"]]
        if field in ("setupTag", "teardownTag") and isinstance(value, list):
            return [f"\"{s.get('tagName')}\"" + (f" ({self.words['stop']})" if s.get("stopOnSetupFailure") or
                                                 s.get("stopTeardownOnFailure") else "") for s in value]
        if field == "parentFolderId":
            return [f"\"{self.name(value if str(value).startswith('new:') else f'folder:{value}')}\""]
        if isinstance(value, dict) and value.get("type") == "MAP":
            return [self._row(value)]
        if isinstance(value, dict) and set(value) <= {"type", "key", "value"}:
            return self.value(field, value.get("value", ""))
        if isinstance(value, list) and value and all(isinstance(v, dict) and v.get("type") == "MAP" for v in value):
            return [self._row(v) for v in value]
        if isinstance(value, str) and value in ENUMS:
            return [self.pick(ENUMS[value])]
        if isinstance(value, bool):
            return [self.words["yes" if value else "no"]]
        if isinstance(value, str):
            return [f"\"{value}\""]
        return [json.dumps(value, ensure_ascii=False)]

    @staticmethod
    def _join(lines: list[str]) -> str:
        return lines[0] if len(lines) == 1 else "\n" + "\n".join(f"   - {line}" for line in lines)

    # ---------- steps ----------

    def at(self, names: dict[str, str]) -> Interface:
        """The same wording with object names as they are in a given state (see `operations.trace`)."""
        view = copy.copy(self)
        view.current = names
        return view

    def steps(self, trace: list, code_of=lambda step: "") -> list[str]:
        """One instruction per traced action, in execution order. The same field change on several objects is one
        instruction listing them, joined only when moving it next to the others cannot change any result: every
        action it moves past writes another object or an unrelated field. `code_of(step)` names its code row."""
        groups: list[tuple[tuple | None, list]] = []
        for step in trace:
            sig = self._signature(step.action)
            for i in range(len(groups) - 1, -1, -1):
                if sig and groups[i][0] == sig:
                    groups[i][1].append(step)
                    break
                if not all(_commute(m.action, step.action) for m in groups[i][1]):
                    groups.append((sig, [step]))
                    break
            else:
                groups.append((sig, [step]))
        return [self._group(members, code_of) for _, members in groups]

    def _signature(self, a: dict) -> tuple | None:
        if a["do"] in WRITES and self._top(a["path"]) not in CODE_FIELDS:
            return (a["do"], a["path"], json.dumps(a.get("value"), sort_keys=True, ensure_ascii=False))
        return (a["do"],) if a["do"] in STATE else None

    def _group(self, members: list, code_of) -> str:
        first = members[0]
        if len(members) == 1:
            return self.at(first.names).step(first.action, code_of(first), first.consumers)
        a, w, view = mask_action(first.action), self.words, self.at(first.names)
        head = w[f"{a['do']}_many"].format(n=len(members), field=view.field(a.get("path", "")),
                                           value=view._join(view.value(view._top(a.get("path", "")), a.get("value"))))
        return "\n".join([head] + [f"   - {self.at(m.names).label(m.action['object'])}" for m in members])

    @staticmethod
    def _top(path: str) -> str:
        return segments(path)[0].removeprefix("parameter:") if path else ""

    def step(self, action: dict, code: str = "", consumers: list[str] | None = None) -> str:
        """One action as one step in GTM interface terms. `code` names where its code is; `consumers` are the
        objects a remap repoints, as they are in the state the action applies to."""
        a, w = mask_action(action), self.words
        kind = a["do"]
        if kind in ("set", "add", "remove"):
            obj, field = self.label(a["object"]), self.field(a["path"])
            if kind == "remove":
                return w["remove"].format(obj=obj, field=field)
            top = self._top(a["path"])
            return w[kind].format(obj=obj, field=field,
                                  value=self._join(self.value(top, a["value"], code if top in CODE_FIELDS else "")))
        if kind == "create":
            obj = a["object"]
            head = w["create"].format(layer=self.pick(LAYERS[a["layer"]]).lower(), name=obj.get("name", ""),
                                      type=self.type_name(a["layer"], str(obj.get("type", ""))))
            lines = []
            for key, value in obj.items():
                if key in ("name", "type") or key in GENERATED or value in (None, "", [], {}):
                    continue
                if key == "parameter":
                    for p in value:
                        pkey = p.get("key", "")
                        shown = p.get("list", p.get("map", p.get("value")))
                        lines.append(f"{self.pick(PARAMS[pkey]) if pkey in PARAMS else pkey}: "
                                     f"{'; '.join(self.value(pkey, shown, code if pkey in CODE_FIELDS else ''))}")
                else:
                    lines.append(f"{self.field(key)}: {'; '.join(self.value(key, value))}")
            return head + ("\n" + "\n".join(f"   - {line}" for line in lines) if lines else "")
        if kind == "rename":
            return w["rename"].format(obj=self.label(a["object"]), name=a["name"])
        if kind == "remap":
            keys = consumers if consumers is not None else [k for k, _ in self.model.consumers(a["from"])]
            users = [self.label(k) for k in keys]
            return w["remap"].format(src=self.label(a["from"]), dst=self.label(a["to"]),
                                     users=", ".join(users) if users else w["nowhere"])
        return w[kind].format(obj=self.label(a["object"]))


def _commute(x: dict, y: dict) -> bool:
    """Two actions can swap places without changing any result: both write fields, on different objects or on
    fields neither of which contains the other."""
    if x["do"] not in WRITES or y["do"] not in WRITES:
        return False
    if x["object"] != y["object"]:
        return True
    a, b = segments(x["path"]), segments(y["path"])
    return a[:len(b)] != b[:len(a)]
