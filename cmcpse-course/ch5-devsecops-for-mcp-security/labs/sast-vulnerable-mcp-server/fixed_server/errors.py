"""Errors whose message is safe to show to the client."""


class ToolInputError(Exception):
    """The client sent something we refuse. `public_message` is safe to return."""

    def __init__(self, public_message: str):
        super().__init__(public_message)
        self.public_message = public_message
