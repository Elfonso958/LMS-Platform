from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
import os
from app.models import db, DocumentType, DocumentReviewRequest, User, UserHRTask, HRTaskTemplate
from app.forms import DocumentTypeForm, FormUpload, DirectDocumentUploadForm
from app.email_utils import send_email
from app.utils import admin_required

from werkzeug.utils import secure_filename
from sqlalchemy.orm import aliased
from collections import defaultdict


document_bp = Blueprint("document", __name__)


@document_bp.route('/document_types', methods=['GET', 'POST'])
@login_required
def manage_document_types():
    form = DocumentTypeForm()
    if form.validate_on_submit():
        new_type = DocumentType(name=form.name.data.strip())
        db.session.add(new_type)
        db.session.commit()
        flash('Document type added.', 'success')
        return redirect(url_for('document.manage_document_types'))

    document_types = DocumentType.query.order_by(DocumentType.name.asc()).all()
    return render_template("documents/manage_document_types.html", form=form, document_types=document_types)


@document_bp.route('/document_types/<int:id>/update', methods=['POST'])
@login_required
def update_document_type(id):
    doc_type = DocumentType.query.get_or_404(id)
    doc_type.name = request.form['name'].strip()
    db.session.commit()
    flash('Document type updated.', 'success')
    return redirect(url_for('document.manage_document_types'))


@document_bp.route('/document_types/<int:id>/delete')
@login_required
def delete_document_type(id):
    doc_type = DocumentType.query.get_or_404(id)
    db.session.delete(doc_type)
    db.session.commit()
    flash('Document type deleted.', 'warning')
    return redirect(url_for('document.manage_document_types'))


@document_bp.route("/user_documents")
@login_required
def user_documents():
    selected_id = request.args.get('selected', type=int)

    doc_alias = aliased(DocumentReviewRequest)
    users_with_docs = (
        db.session.query(User)
        .join(doc_alias, User.id == doc_alias.user_id)
        .filter(doc_alias.status == 'approved')
        .distinct()
        .all()
    )

    grouped_docs = {}
    for user in users_with_docs:
        docs = DocumentReviewRequest.query.filter_by(
            user_id=user.id, status='approved'
        ).order_by(DocumentReviewRequest.submitted_at.desc()).all()

        doc_groups = defaultdict(list)
        for doc in docs:
            doc_groups[doc.type.name if doc.type else "Other"].append(doc)

        grouped_docs[user.id] = {
            "user": user,
            "documents": doc_groups
        }

    document_types = DocumentType.query.order_by(DocumentType.name).all()

    return render_template(
        "documents/user_documents.html",
        grouped_docs=grouped_docs,
        selected_id=selected_id,
        document_types=document_types
    )


@document_bp.route("/upload_document_admin", methods=["POST"])
@login_required
def upload_document_admin():
    file = request.files.get("file")
    document_type_id = request.form.get("document_type_id")
    expiry_date = request.form.get("document_expiry_date")
    user_id = request.form.get("user_id")

    if not all([file, document_type_id, expiry_date, user_id]):
        flash("Missing fields for document upload.", "danger")
        return redirect(url_for("document.user_documents"))

    user = User.query.get(user_id)
    document_type = DocumentType.query.get(document_type_id)

    if not user or not document_type:
        flash("Invalid user or document type.", "danger")
        return redirect(url_for("document.user_documents"))

    doc_type_name = secure_filename(document_type.name)
    username = secure_filename(user.username)
    formatted_date = datetime.strptime(expiry_date, "%Y-%m-%d").strftime("%Y-%m-%d")

    extension = os.path.splitext(file.filename)[1]
    renamed_filename = secure_filename(f"{doc_type_name} - {user.username} - {formatted_date}{extension}")

    upload_folder = os.path.join(current_app.static_folder, 'uploads', user.username, doc_type_name)
    os.makedirs(upload_folder, exist_ok=True)

    full_path = os.path.join(upload_folder, renamed_filename)
    file.save(full_path)

    relative_path = f"uploads/{user.username}/{doc_type_name}/{renamed_filename}"

    new_doc = DocumentReviewRequest(
        user_id=user.id,
        document_type_id=document_type.id,
        document_expiry_date=formatted_date,
        file_path=relative_path,
        submitted_at=datetime.utcnow(),
        status='approved'
    )
    db.session.add(new_doc)
    db.session.commit()

    flash(f"{document_type.name} uploaded for {user.username}.", "success")
    return redirect(url_for("document.user_documents"))

@document_bp.route("/review_documents", methods=["GET", "POST"])
@login_required
def review_documents():
    page        = request.args.get("page", 1, type=int)
    filter_type = request.args.get("filter", "", type=str)

    if request.method == "POST":
        # 1) Bulk‐update the DocumentReviewRequest records
        ids        = request.form.get("doc_ids", "")
        new_status = request.form.get("action")
        comment    = request.form.get("comment", "")
        doc_ids    = [int(i) for i in ids.split(",") if i]
        docs       = DocumentReviewRequest.query.filter(
                        DocumentReviewRequest.id.in_(doc_ids)
                     ).all()

        for doc in docs:
            doc.status         = new_status
            doc.review_comment = comment
            doc.reviewed_by_id = current_user.id
            doc.reviewed_at    = datetime.utcnow()

            # if rejected, delete the file
            if new_status == 'reject' and doc.file_path:
                full = (
                    doc.file_path
                    if os.path.isabs(doc.file_path)
                    else os.path.join(current_app.static_folder,
                                      doc.file_path.lstrip("/"))
                )
                if os.path.exists(full):
                    os.remove(full)

        # 2) Re‐open or complete the matching HR task(s) for that user+doctype
        if docs:
            user_id     = docs[0].user_id
            doc_type_id = docs[0].document_type_id

            tasks = UserHRTask.query.join(HRTaskTemplate).filter(
                        UserHRTask.user_id               == user_id,
                        HRTaskTemplate.document_type_id  == doc_type_id
                    ).all()

            for t in tasks:
                if new_status == 'approved':
                    t.status       = 'Completed'
                    t.completed_by = current_user.username
                    t.completed_at = datetime.utcnow()
                else:  # reject → reopen
                    t.status       = 'Pending'
                    t.completed_by = None
                    t.completed_at = None

        db.session.commit()
        flash(f"Document(s) {new_status.capitalize()}!", "success")
        return redirect(url_for("document.review_documents",
                                page=page, filter=filter_type))

    # ─── GET: page & filter ───────────────────────────────────────────────────
    query = DocumentReviewRequest.query.filter_by(status="pending")
    if filter_type:
        try:
            dtid = int(filter_type)
            query = query.filter_by(document_type_id=dtid)
        except ValueError:
            pass

    pending_docs = query\
        .order_by(DocumentReviewRequest.submitted_at.desc())\
        .paginate(page=page, per_page=10)

    # group only this page’s items by (user, doctype, expiry)
    buckets = defaultdict(list)
    for d in pending_docs.items:
        key = (d.user_id, d.document_type_id, d.document_expiry_date)
        buckets[key].append(d)

    pending_groups = []
    for (uid, dtid, expiry), docs in buckets.items():
        pending_groups.append({
            "user":          docs[0].user,
            "document_type": docs[0].type,
            "expiry_date":   expiry,
            "submitted_at":  docs[0].submitted_at,
            "doc_ids":       ",".join(str(d.id) for d in docs),
            "files":         docs
        })

    document_types = DocumentType.query.order_by(DocumentType.name).all()
    return render_template(
        "documents/review_documents.html",
        pending_docs    = pending_docs,
        pending_groups  = pending_groups,
        document_types  = document_types,
        filter          = filter_type
    )

########################
###DOCUMENT UPLOAD###
#######################
# app/routes/document_routes.py

@document_bp.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    form = FormUpload()

    # ── Load and bind all document types ───────────────────────
    doc_types = DocumentType.query.order_by(DocumentType.name).all()
    form.document_type.choices = [(dt.id, dt.name) for dt in doc_types]

    # ── Allow pre‐selection (so your “Complete” link can pass task_id & document_type) ──
    task_id    = request.args.get('task_id',        type=int)
    pre_doc_id = request.args.get('document_type',  type=int)
    if request.method == 'GET' and pre_doc_id:
        form.document_type.data = pre_doc_id

    # ── Compute how many pages we ought to render ─────────────
    pages_required = 1
    if form.document_type.data:
        dt = next((d for d in doc_types if d.id == form.document_type.data), None)
        pages_required = dt.pages_required or 1

    if request.method == 'POST':
        # only validate those two fields:
        if not form.document_type.data or not form.document_expiry_date.data:
            flash("Please choose a document type and expiry date.", "danger")
            return render_template(
                'documents/upload_document.html',
                form            = form,
                pages_required  = pages_required,
                doc_types       = doc_types
            )

        # now fetch all files[] inputs
        files = request.files.getlist('files[]')
        if len(files) != pages_required or any(f.filename == '' for f in files):
            flash(f"Please upload all {pages_required} page(s).", "danger")
            return render_template(
                'documents/upload_document.html',
                form            = form,
                pages_required  = pages_required,
                doc_types       = doc_types
            )

        # ── Save each page + insert DocumentReviewRequest ────────
        document_type_id = form.document_type.data
        expiry_date      = form.document_expiry_date.data
        dt_obj           = DocumentType.query.get(document_type_id)
        dt_name          = secure_filename(dt_obj.name)
        user_name        = secure_filename(current_user.username)
        date_str         = expiry_date.strftime('%Y-%m-%d')

        for idx, file in enumerate(files, start=1):
            ext      = os.path.splitext(file.filename)[1]
            filename = f"{dt_name}-page{idx}-of{pages_required}-{user_name}-{date_str}{ext}"
            upload_folder = os.path.join(
                current_app.static_folder, 'uploads', user_name, dt_name
            )
            os.makedirs(upload_folder, exist_ok=True)
            full_path = os.path.join(upload_folder, filename)
            file.save(full_path)

            rel_path = f"uploads/{user_name}/{dt_name}/{filename}"
            new_req  = DocumentReviewRequest(
                user_id              = current_user.id,
                document_type_id     = document_type_id,
                document_expiry_date = expiry_date,
                file_path            = rel_path,
                submitted_at         = datetime.utcnow(),
                status               = 'pending'
            )
            db.session.add(new_req)
        db.session.commit()

        # ── Auto‐complete the HR task(s) ────────────────────────
        if task_id:
            t = UserHRTask.query.get(task_id)
            if t and t.status == 'Pending':
                t.status        = 'Completed'
                t.completed_by  = current_user.username
                t.completed_at  = datetime.utcnow()
                db.session.commit()
                flash("Document uploaded & task auto‑completed.", "success")
            else:
                flash("Document uploaded, but that task was already completed.", "info")
        else:
            pending = (
                UserHRTask.query
                .join(HRTaskTemplate, UserHRTask.task_template)
                .filter(
                    UserHRTask.user_id              == current_user.id,
                    UserHRTask.status               == 'Pending',
                    HRTaskTemplate.document_type_id == document_type_id
                )
                .all()
            )
            for t in pending:
                t.status        = 'Completed'
                t.completed_by  = current_user.username
                t.completed_at  = datetime.utcnow()
            db.session.commit()
            flash(f"Document uploaded & {len(pending)} task(s) auto‑completed.", "success")

        return redirect(url_for('user.user_dashboard'))

    return render_template(
        'documents/upload_document.html',
        form            = form,
        pages_required  = pages_required,
        doc_types       = doc_types
    )
