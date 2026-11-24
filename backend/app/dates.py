"""Small date helpers shared by the API and the demo data."""

from datetime import date


def months_back(n: int, today: date | None = None) -> list[date]:
    """The first days of the last `n` months, oldest first, this month last."""
    t = (today or date.today()).replace(day=1)
    out = []
    for k in range(n - 1, -1, -1):
        y, m = divmod(t.year * 12 + t.month - 1 - k, 12)
        out.append(date(y, m + 1, 1))
    return out
