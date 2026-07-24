"""Exceções do Intelligence Hub."""


class IntelligenceError(Exception):
    """Erro genérico do hub."""


class SurfaceNotFound(IntelligenceError):
    """Attack Surface inexistente para o alvo."""


class StorageUnavailable(IntelligenceError):
    """Backend de storage indisponível (ex.: DATABASE_URL ausente)."""
