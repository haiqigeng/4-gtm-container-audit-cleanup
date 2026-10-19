"""GTM interface wording of actions."""


from conftest import SECRET, ce_trigger, operation, p

from gtmaudit import operations


def test_steps_speak_the_gtm_interface(model):
    from gtmaudit.steps import Interface
    created = {"do": "create", "layer": "trigger", "ref": "new:trigger:block",
               "object": ce_trigger("", "Block - ads", "x")}
    ui = Interface(model, [operation(actions=[created])], "en")
    exceptions = {"do": "set", "object": "tag:2", "path": "blockingTriggerId", "value": ["new:trigger:block"]}
    assert ui.step(exceptions) == 'Tag "GA4 - purchase": set Triggering › Exceptions to "Block - ads"'
    row = {"do": "remove", "object": "tag:2", "path": "parameter:eventSettingsTable.list.row:parameter=value"}
    assert ui.step(row) == 'Tag "GA4 - purchase": remove Event parameters › row "value"'
    condition = {"do": "set", "object": "trigger:12", "path": "filter[0].parameter:arg1.value", "value": "^iab:91$"}
    assert ui.step(condition) == ('Trigger "Block - consent": set This trigger fires on › Some events › condition 1 '
                                  '› value to "^iab:91$"')
    negated = {"do": "set", "object": "trigger:12", "path": "filter", "value": [
        {"type": "EQUALS", "parameter": [p("arg0", "{{x}}"), p("arg1", "granted"), p("negate", "true", "BOOLEAN")]}]}
    assert ui.step(negated).endswith('{{x}} does not equal "granted"')
    assert ui.cite("tag:2 fires on trigger:2147479553 and new:trigger:block") == \
        'Tag "GA4 - purchase" fires on Trigger "All Pages" and Trigger "Block - ads"'
    family = [{"do": "add", "object": f"tag:{i}", "path": "blockingTriggerId", "value": "12"} for i in (2, 4, 6)]
    cleanup = [{"do": "delete", "object": "trigger:13"}, {"do": "delete", "object": "variable:22"}]
    traced = operations.trace(model, [operation(actions=family + cleanup)])["D4-OP01"]
    assert ui.steps(traced) == [
        "\n".join(['In Triggering › Exceptions, add "Block - consent" on these 3 objects:', '   - Tag "GA4 - purchase"',
                   '   - Tag "Vendor - cart"', '   - Tag "Vendor - template tag"']),
        "\n".join(["Delete these 2 objects:", '   - Trigger "CE - purchase copy"', '   - Variable "Unused constant"'])]
    fr = Interface(model, [], "fr")
    cap = {"do": "set", "object": "tag:4", "path": "tagFiringOption", "value": "ONCE_PER_EVENT"}
    assert fr.step(cap) == ("Balise « Vendor - cart » : définir Paramètres avancés › Options de déclenchement de la "
                            "balise sur Une fois par événement")


def test_scalar_values_take_their_field_identity_from_the_path(model):
    from gtmaudit.privacy import mask_action
    from gtmaudit.steps import Interface
    action = {"do": "set", "object": "tag:2", "value": SECRET,
              "path": "parameter:eventSettingsTable.list.row:parameter=client_secret.map:parameterValue.value"}
    assert SECRET not in str(mask_action(action))
    assert SECRET not in Interface(model, [], "en").step(action)


def test_instructions_keep_action_order_and_group_only_commuting_writes(model):
    from gtmaudit.steps import Interface
    notes = [{"do": "set", "object": "tag:3", "path": "notes", "value": v} for v in ("A", "B", "A")]
    family = [{"do": "set", "object": "tag:2", "path": "notes", "value": "Z"},
              {"do": "set", "object": "tag:3", "path": "notes", "value": "Y"},
              {"do": "set", "object": "tag:4", "path": "notes", "value": "Z"}]
    ui = Interface(model, [], "en")
    aba = ui.steps(operations.trace(model, [operation(actions=notes)])["D4-OP01"])
    assert [s.rsplit(" ", 1)[1] for s in aba] == ['"A"', '"B"', '"A"']
    grouped = ui.steps(operations.trace(model, [operation(actions=family)])["D4-OP01"])
    assert len(grouped) == 2 and 'Tag "GA4 - purchase"' in grouped[0] and 'Tag "Vendor - cart"' in grouped[0]
