from charm.toolbox.pairinggroup import G1, G2, GT, ZR, PairingGroup, pair

group = PairingGroup("SS512")
zero = group.init(ZR, 0)


class Polynomial:
    def __init__(self, coefs):
        self.coefs = [
            group.init(ZR, coef) if type(coef) is int else coef for coef in coefs
        ]
        while len(self.coefs) > 1 and self.coefs[-1] == zero:
            self.coefs.pop()

    @property
    def degree(self):
        return len(self.coefs) - 1

    def coef(self, i):
        if i < len(self.coefs):
            return self.coefs[i]
        return zero

    def evaluate(self, x):
        if type(x) is int:
            x = group.init(ZR, x)
        result = zero
        for deg, coef in enumerate(self.coefs):
            result += coef * x ** deg
        return result

    def copy(self):
        return Polynomial(self.coefs)

    def evaluate_encrypted(self, g, encrypted_monomials):
        assert len(encrypted_monomials) >= self.degree
        result = g ** self.coefs[0]
        for coef, encrypted_monomial in zip(self.coefs[1:], encrypted_monomials):
            result *= encrypted_monomial ** coef
        return result

    def __eq__(self, other):
        if type(other) is not Polynomial:
            return NotImplementedError
        return self.degree == other.degree and all(
            self.coefs[i] == other.coefs[i] for i in range(self.degree + 1)
        )

    def __add__(self, other):
        if type(other) is not Polynomial:
            return NotImplementedError
        return Polynomial(
            [
                self.coef(i) + other.coef(i)
                for i in range(max(self.degree, other.degree) + 1)
            ]
        )

    def __sub__(self, other):
        if type(other) is not Polynomial:
            return NotImplementedError
        return Polynomial(
            [
                self.coef(i) - other.coef(i)
                for i in range(max(self.degree, other.degree) + 1)
            ]
        )

    def __mul__(self, other):
        if type(other) is int:
            return Polynomial([other * coef for coef in self.coefs])
        if type(other) is not Polynomial:
            return NotImplementedError
        coefs = [0] * (self.degree + other.degree + 1)
        for i in range(self.degree + 1):
            for j in range(other.degree + 1):
                coefs[i + j] += self.coefs[i] * other.coefs[j]
        return Polynomial(coefs)

    def __rmul__(self, other):
        if type(other) is not int:
            return NotImplementedError
        return self.__mul__(other)

    def __divmod__(self, other):
        if type(other) is not Polynomial:
            return NotImplementedError
        if self.degree < other.degree:
            return Polynomial([0]), self.copy()
        else:
            factor = self.coefs[-1] / other.coefs[-1]
            quotient_monomial = Polynomial(
                [0] * (self.degree - other.degree) + [factor]
            )
            remaining = self - quotient_monomial * other
            if self.degree == other.degree:
                return quotient_monomial, remaining
            quotient, remainder = divmod(remaining, other)
            return quotient_monomial + quotient, remainder

    def __str__(self):
        result = ""
        for deg, coef in enumerate(self.coefs):
            if coef == zero and len(self.coefs) > 1:
                continue
            result = (
                str(coef)
                + ("x" if deg > 0 else "")
                + (f"^{deg}" if deg > 1 else "")
                + (" + " if result != "" else "")
                + result
            )
        return result

    def __repr__(self):
        return f"<{self.__str__()}>"
