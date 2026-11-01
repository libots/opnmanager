import json
from django import forms
from .reconcile import validate_snapshot

class SnapshotImportForm(forms.Form):
    snapshot = forms.FileField(help_text="Normalized JSON snapshot (schema version 1), maximum 5 MiB.")
    def clean_snapshot(self):
        upload = self.cleaned_data["snapshot"]
        if upload.size > 5 * 1024 * 1024:
            raise forms.ValidationError("Snapshot exceeds 5 MiB.")
        try:
            return validate_snapshot(json.load(upload))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise forms.ValidationError("Invalid snapshot JSON: " + str(exc))
