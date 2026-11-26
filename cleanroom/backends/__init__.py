from .base import Backend, RunResult, RunSpec

__all__ = ["Backend", "RunResult", "RunSpec", "get_backend"]


def get_backend(name: str, project, **kw) -> "Backend":
    if name == "local":
        from .local import LocalBackend
        return LocalBackend(project, **kw)
    if name == "sprite":
        from .sprite import SpriteBackend
        return SpriteBackend(project, **kw)
    raise ValueError(f"unknown backend {name!r} (use 'local' or 'sprite')")
