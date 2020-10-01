from crypto import G1, ZR, Polynomial, group, pair


class Problem:
    def __init__(self, t, max_order):
        self.g = group.random(G1)
        self.g.initPP()
        self.t = t
        self.max_order = max_order

    def trusted_setup(self):
        s = group.random(ZR)
        alpha = group.random(ZR)
        monomials = [s ** i for i in range(1, self.max_order + 1)]
        encrypted_monomials = [self.g ** s_i for s_i in monomials]
        shifted_encrypted_monomials = [
            encrypted_monomial ** alpha
            for encrypted_monomial in ([self.g] + encrypted_monomials)
        ]
        encrypted_t_s = self.g ** self.t.evaluate(s)
        proving_key = [encrypted_monomials, shifted_encrypted_monomials]
        verification_key = [shifted_encrypted_monomials[0], encrypted_t_s]
        return [proving_key, verification_key]


class Prover:
    def __init__(self, problem, proving_key):
        self.problem = problem
        self.encrypted_monomials, self.shifted_encrypted_monomials = proving_key

    def prove(self, p):
        assert p.degree <= self.problem.max_order
        h, remainder = divmod(p, self.problem.t)
        assert remainder == Polynomial([0])
        delta = group.random(ZR)
        return [
            p.evaluate_encrypted(self.problem.g, self.encrypted_monomials) ** delta,
            h.evaluate_encrypted(self.problem.g, self.encrypted_monomials) ** delta,
            p.evaluate_encrypted(
                self.shifted_encrypted_monomials[0],
                self.shifted_encrypted_monomials[1:],
            )
            ** delta,
        ]


class Verifier:
    def __init__(self, problem, verification_key):
        self.problem = problem
        self.encrypted_alpha, self.encrypted_t_s = verification_key

    def verify(self, proof):
        [encrypted_p, encrypted_h, shifted_encrypted_p] = proof
        assert pair(shifted_encrypted_p, self.problem.g) == pair(
            encrypted_p, self.encrypted_alpha
        )
        assert pair(encrypted_p, self.problem.g) == pair(
            self.encrypted_t_s, encrypted_h
        )


if __name__ == "__main__":
    t = Polynomial([-1, 1]) * Polynomial([-2, 1])
    problem = Problem(t, max_order=3)
    proving_key, verification_key = problem.trusted_setup()
    prover = Prover(problem, proving_key)
    verifier = Verifier(problem, verification_key)

    p = Polynomial([0, 2, -3, 1])
    proof = prover.prove(p)
    verifier.verify(proof)
    print("p24 example successful.")
