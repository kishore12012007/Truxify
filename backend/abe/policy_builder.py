
import re


class CpAbePolicyBuilder:
    """
    Builds and evaluates boolean access policies
    using logistics attributes.
    """

    MAX_POLICY_LENGTH = 4096

    def build_trip_document_policy(
        self, trip_id: str, allowed_role: str = "Driver"
    ) -> str:

        if not isinstance(trip_id, str) or not trip_id.strip():
            raise ValueError("Trip ID cannot be empty")

        if not isinstance(allowed_role, str) or not allowed_role.strip():
            raise ValueError("Role cannot be empty")

        # Prevent policy injection through input values.
        reserved = re.compile(r"\b(AND|OR|NOT)\b|[()]", re.IGNORECASE)

        if reserved.search(trip_id) or reserved.search(allowed_role):
            raise ValueError("Trip ID and role cannot contain policy operators")

        trip_id = trip_id.strip()
        allowed_role = allowed_role.strip()

        return (
            f"(Role: {allowed_role} AND TripID: {trip_id}) "
            f"OR Role: Admin"
        )

    def evaluate_user_attributes(
        self, user_attributes: set, policy_str: str
    ) -> bool:

        if not isinstance(user_attributes, set):
            raise TypeError("User attributes must be a set")

        if not all(
            isinstance(attr, str) and attr.strip()
            for attr in user_attributes
        ):
            raise ValueError("All user attributes must be non-empty strings")

        if not isinstance(policy_str, str) or not policy_str.strip():
            raise ValueError("Policy cannot be empty")

        if len(policy_str) > self.MAX_POLICY_LENGTH:
            raise ValueError("Policy is too long")

        tokens = self._tokenize(policy_str)

        parser = _BooleanParser(tokens, user_attributes)

        return parser.parse()

    def _tokenize(self, expr: str) -> list:

        pattern = r"\s*(\(|\)|\bAND\b|\bOR\b|\bNOT\b)"

        parts = re.split(pattern, expr, flags=re.IGNORECASE)

        tokens = []

        for part in parts:
            part = part.strip()

            if not part:
                continue

            if part == "(":
                tokens.append(("LP", None))

            elif part == ")":
                tokens.append(("RP", None))

            elif part.upper() in ("AND", "OR", "NOT"):
                tokens.append((part.upper(), None))

            else:
                tokens.append(("ATTR", part))

        return tokens


class _BooleanParser:
    """
    Recursive-descent parser.

    Precedence:
        NOT > AND > OR
    """

    def __init__(self, tokens, user_attributes):
        self.tokens = tokens
        self.user = user_attributes
        self.pos = 0

    def _peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]

        return (None, None)

    def _advance(self):
        if self.pos >= len(self.tokens):
            raise ValueError("Unexpected end of policy")

        token = self.tokens[self.pos]
        self.pos += 1

        return token

    def parse(self):

        if not self.tokens:
            raise ValueError("Empty policy")

        result = self._parse_or()

        if self.pos != len(self.tokens):
            raise ValueError("Invalid policy expression")

        return result

    def _parse_or(self):

        value = self._parse_and()

        while self._peek()[0] == "OR":
            self._advance()
            right = self._parse_and()
            value = value or right

        return value

    def _parse_and(self):

        value = self._parse_not()

        while self._peek()[0] == "AND":
            self._advance()
            right = self._parse_not()
            value = value and right

        return value

    def _parse_not(self):

        if self._peek()[0] == "NOT":
            self._advance()
            return not self._parse_not()

        return self._parse_primary()

    def _parse_primary(self):

        token_type, token_value = self._peek()

        if token_type == "LP":
            self._advance()

            value = self._parse_or()

            if self._peek()[0] != "RP":
                raise ValueError("Missing closing parenthesis")

            self._advance()

            return value

        if token_type == "ATTR":
            self._advance()
            return token_value in self.user

        raise ValueError("Invalid policy expression")


policy_builder = CpAbePolicyBuilder()
