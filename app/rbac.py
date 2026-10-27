"""Permission and role definitions (RBAC). Source of truth for the seed script and the report."""

ARTICLES_READ = "articles:read"
ARTICLES_CREATE = "articles:create"
ARTICLES_EDIT = "articles:edit"
ARTICLES_DELETE = "articles:delete"
USERS_READ = "users:read"
USERS_MANAGE = "users:manage"
SETTINGS_MANAGE = "settings:manage"
AUDIT_READ = "audit:read"

PERMISSIONS: dict[str, str] = {
    ARTICLES_READ: "Odczyt artykułów",
    ARTICLES_CREATE: "Tworzenie artykułów",
    ARTICLES_EDIT: "Edycja artykułów",
    ARTICLES_DELETE: "Usuwanie artykułów",
    USERS_READ: "Podgląd listy użytkowników",
    USERS_MANAGE: "Zarządzanie użytkownikami",
    SETTINGS_MANAGE: "Zmiana ustawień bezpieczeństwa",
    AUDIT_READ: "Odczyt dziennika zdarzeń (moduł 2)",
}

ROLE_ADMIN = "Administrator"
ROLE_AUDITOR = "Audytor"
ROLE_EDITOR = "Redaktor"
ROLE_READER = "Czytelnik"

ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_ADMIN: set(PERMISSIONS),
    ROLE_AUDITOR: {ARTICLES_READ, USERS_READ, AUDIT_READ},
    ROLE_EDITOR: {ARTICLES_READ, ARTICLES_CREATE, ARTICLES_EDIT, ARTICLES_DELETE},
    ROLE_READER: {ARTICLES_READ},
}
