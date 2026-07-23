from datetime import date

from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db
from app.models.remediation_action import (
    ACTION_STATUSES,
    ACTION_TYPES,
    APPROVAL_STATUSES,
    PRIORITIES,
    RemediationAction,
)
from app.models.threat import Threat
from app.repositories import RemediationActionRepository
from app.services.remediation_actions import (
    DuplicateRemediationActionError,
    RemediationActionService,
)

from . import actions_blueprint


def _form_options():
    return {
        "action_types": ACTION_TYPES,
        "priorities": PRIORITIES,
        "statuses": ACTION_STATUSES,
        "approval_statuses": APPROVAL_STATUSES,
        "threats": RemediationActionRepository.list_threats(),
    }


def _form_values(action=None, threat_id=None):
    if action is None:
        return {
            "ThreatId": str(threat_id or ""),
            "Title": "",
            "Description": "",
            "ActionType": "Patch",
            "Priority": "High",
            "Status": "Open",
            "Owner": "",
            "DueDate": "",
            "ApprovalStatus": "Not Required",
            "TicketReference": "",
            "Notes": "",
        }
    return {
        field: (
            action.DueDate.isoformat()
            if field == "DueDate" and action.DueDate
            else getattr(action, field) or ""
        )
        for field in (
            "ThreatId",
            "Title",
            "Description",
            "ActionType",
            "Priority",
            "Status",
            "Owner",
            "DueDate",
            "ApprovalStatus",
            "TicketReference",
            "Notes",
        )
    }


@actions_blueprint.get("/")
def action_list():
    due_date_text = request.args.get("due_date", "").strip()
    due_date = None
    if due_date_text:
        try:
            due_date = date.fromisoformat(due_date_text)
        except ValueError:
            due_date_text = ""
    filters = {
        "status": request.args.get("status", "").strip(),
        "priority": request.args.get("priority", "").strip(),
        "owner": request.args.get("owner", "").strip(),
        "due_date": due_date,
        "threat_id": request.args.get("threat_id", type=int),
    }
    if filters["status"] not in ACTION_STATUSES:
        filters["status"] = ""
    if filters["priority"] not in PRIORITIES:
        filters["priority"] = ""
    return render_template(
        "actions.html",
        actions=RemediationActionRepository.list_actions(filters),
        filters={**filters, "due_date": due_date_text},
        statuses=ACTION_STATUSES,
        priorities=PRIORITIES,
        threats=RemediationActionRepository.list_threats(),
    )


@actions_blueprint.route("/new", methods=["GET", "POST"])
def create_action():
    threat_id = request.args.get("threat_id", type=int)
    values = _form_values(threat_id=threat_id)
    errors = {}
    if request.method == "POST":
        values = RemediationActionService.parse_form(request.form)
        errors = RemediationActionService.validate(values)
        if not errors and db.session.get(Threat, values["ThreatId"]) is None:
            errors["threat_id"] = "Select a valid threat."
        if not errors:
            try:
                action = RemediationActionService().create(values)
            except DuplicateRemediationActionError as exc:
                errors["title"] = str(exc)
            else:
                flash("Remediation action created.", "success")
                return redirect(
                    url_for(
                        "actions.action_detail",
                        action_id=action.ActionId,
                    )
                )
    return render_template(
        "action_form.html",
        page_title="Create Remediation Action",
        values=values,
        errors=errors,
        **_form_options(),
    )


@actions_blueprint.get("/<int:action_id>")
def action_detail(action_id):
    action = RemediationActionRepository.get(action_id)
    if action is None:
        return "", 404
    return render_template(
        "action_detail.html",
        action=action,
        statuses=ACTION_STATUSES,
    )


@actions_blueprint.route(
    "/<int:action_id>/edit", methods=["GET", "POST"]
)
def edit_action(action_id):
    action = db.get_or_404(RemediationAction, action_id)
    values = _form_values(action=action)
    errors = {}
    if request.method == "POST":
        values = RemediationActionService.parse_form(request.form)
        errors = RemediationActionService.validate(values)
        if not errors and db.session.get(Threat, values["ThreatId"]) is None:
            errors["threat_id"] = "Select a valid threat."
        if not errors:
            try:
                RemediationActionService().update(action, values)
            except DuplicateRemediationActionError as exc:
                errors["title"] = str(exc)
            else:
                flash("Remediation action updated.", "success")
                return redirect(
                    url_for(
                        "actions.action_detail",
                        action_id=action.ActionId,
                    )
                )
    return render_template(
        "action_form.html",
        page_title="Edit Remediation Action",
        values=values,
        errors=errors,
        **_form_options(),
    )


@actions_blueprint.post("/<int:action_id>/status")
def update_status(action_id):
    action = db.get_or_404(RemediationAction, action_id)
    status = request.form.get("status", "").strip()
    try:
        RemediationActionService().update_status(action, status)
    except ValueError as exc:
        flash(str(exc), "danger")
    else:
        flash(f"Action status updated to {status}.", "success")
    return redirect(
        url_for("actions.action_detail", action_id=action_id)
    )


@actions_blueprint.post("/<int:action_id>/complete")
def complete_action(action_id):
    action = db.get_or_404(RemediationAction, action_id)
    RemediationActionService().complete(action)
    flash("Remediation action completed.", "success")
    return redirect(
        url_for("actions.action_detail", action_id=action_id)
    )


@actions_blueprint.post("/<int:action_id>/reopen")
def reopen_action(action_id):
    action = db.get_or_404(RemediationAction, action_id)
    RemediationActionService().reopen(action)
    flash("Remediation action reopened.", "success")
    return redirect(
        url_for("actions.action_detail", action_id=action_id)
    )
