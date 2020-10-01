from crypto import G1, ZR, Polynomial, group, pair


class Problem:
    def __init__(self):
        self.g = group.random(G1)
        self.g.initPP()
        self.num_constraints = 1
        self.t = Polynomial([1])
        for constraint in range(1, self.num_constraints + 1):
            self.t = self.t * Polynomial([-constraint, 1])

    def trusted_setup(self):
        s = group.random(ZR)
        alpha = group.random(ZR)
        monomials_short = [s ** i for i in range(1, self.num_constraints + 1)]
        encrypted_monomials_short = [self.g ** s_i for s_i in monomials_short]
        encrypted_monomials = [self.g] + encrypted_monomials_short
        encrypted_shifted_monomials = [
            encrypted_monomial ** alpha for encrypted_monomial in encrypted_monomials
        ]
        encrypted_t_of_s = self.g ** self.t.evaluate(s)
        proving_key = [encrypted_monomials_short, encrypted_shifted_monomials]
        verification_key = [encrypted_shifted_monomials[0], encrypted_t_of_s]
        return [proving_key, verification_key]


class Prover:
    def __init__(self, problem, proving_key):
        self.problem = problem
        self.encrypted_monomials_short, self.encrypted_shifted_monomials = proving_key

    def prove(self, l_1, r_1, o_1):
        l, r, o = Polynomial([0, l_1]), Polynomial([0, r_1]), Polynomial([0, o_1])
        p = l * r - o
        h, remainder = divmod(p, self.problem.t)
        assert remainder == Polynomial([0])
        return [
            poly.evaluate_encrypted(self.problem.g, self.encrypted_monomials_short)
            for poly in [l, r, o, h]
        ] + [
            poly.evaluate_encrypted(
                self.encrypted_shifted_monomials[0],
                self.encrypted_shifted_monomials[1:],
            )
            for poly in [l, r, o]
        ]


class Verifier:
    def __init__(self, problem, verification_key):
        self.problem = problem
        self.encrypted_alpha, self.encrypted_t_of_s = verification_key

    def verify(self, proof):
        [g_l, g_r, g_o, g_h, g_l_prime, g_r_prime, g_o_prime] = proof
        assert pair(g_l_prime, self.problem.g) == pair(g_l, self.encrypted_alpha)
        assert pair(g_r_prime, self.problem.g) == pair(g_r, self.encrypted_alpha)
        assert pair(g_o_prime, self.problem.g) == pair(g_o, self.encrypted_alpha)
        assert pair(g_l, g_r) == pair(self.encrypted_t_of_s, g_h) * pair(
            g_o, self.problem.g
        )


if __name__ == "__main__":
    problem = Problem()
    proving_key, verification_key = problem.trusted_setup()
    prover = Prover(problem, proving_key)
    verifier = Verifier(problem, verification_key)

    proof = prover.prove(2, 3, 6)
    verifier.verify(proof)
    print("p30 example successful.")
