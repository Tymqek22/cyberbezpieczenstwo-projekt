from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import rbac
from app.db import get_db
from app.deps import AuthContext, require_permission, verify_csrf
from app.models import Article
from app.templating import templates

router = APIRouter(prefix="/articles")


def _get_article(db: Session, article_id: int) -> Article:
    article = db.get(Article, article_id)
    if article is None:
        raise HTTPException(404, "Nie znaleziono artykułu")
    return article


def _validate(title: str) -> list[str]:
    return [] if 1 <= len(title.strip()) <= 200 else ["Tytuł: 1–200 znaków."]


@router.get("")
def article_list(
    request: Request,
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_READ)),
    db: Session = Depends(get_db),
):
    articles = db.scalars(select(Article).order_by(Article.created_at.desc())).all()
    return templates.TemplateResponse(request, "articles/list.html", {"ctx": ctx, "articles": articles})


@router.get("/new")
def article_new_form(request: Request, ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_CREATE))):
    return templates.TemplateResponse(
        request, "articles/form.html", {"ctx": ctx, "article": None, "form": {}, "errors": []}
    )


@router.post("/new", dependencies=[Depends(verify_csrf)])
def article_create(
    request: Request,
    title: str = Form(...),
    body: str = Form(""),
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_CREATE)),
    db: Session = Depends(get_db),
):
    errors = _validate(title)
    if errors:
        return templates.TemplateResponse(
            request,
            "articles/form.html",
            {"ctx": ctx, "article": None, "form": {"title": title, "body": body}, "errors": errors},
            status_code=400,
        )
    article = Article(title=title.strip(), body=body, author_id=ctx.user.id)
    db.add(article)
    db.commit()
    return RedirectResponse(f"/articles/{article.id}", status_code=303)


@router.get("/{article_id}")
def article_detail(
    request: Request,
    article_id: int,
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_READ)),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        request, "articles/detail.html", {"ctx": ctx, "article": _get_article(db, article_id)}
    )


@router.get("/{article_id}/edit")
def article_edit_form(
    request: Request,
    article_id: int,
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_EDIT)),
    db: Session = Depends(get_db),
):
    article = _get_article(db, article_id)
    return templates.TemplateResponse(
        request,
        "articles/form.html",
        {"ctx": ctx, "article": article, "form": {"title": article.title, "body": article.body}, "errors": []},
    )


@router.post("/{article_id}/edit", dependencies=[Depends(verify_csrf)])
def article_update(
    request: Request,
    article_id: int,
    title: str = Form(...),
    body: str = Form(""),
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_EDIT)),
    db: Session = Depends(get_db),
):
    article = _get_article(db, article_id)
    errors = _validate(title)
    if errors:
        return templates.TemplateResponse(
            request,
            "articles/form.html",
            {"ctx": ctx, "article": article, "form": {"title": title, "body": body}, "errors": errors},
            status_code=400,
        )
    article.title = title.strip()
    article.body = body
    db.commit()
    return RedirectResponse(f"/articles/{article.id}", status_code=303)


@router.post("/{article_id}/delete", dependencies=[Depends(verify_csrf)])
def article_delete(
    article_id: int,
    ctx: AuthContext = Depends(require_permission(rbac.ARTICLES_DELETE)),
    db: Session = Depends(get_db),
):
    db.delete(_get_article(db, article_id))
    db.commit()
    return RedirectResponse("/articles", status_code=303)
