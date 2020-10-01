from crypto import G1, ZR, Polynomial, group


class Problem:
    def __init__(self, t, max_order):
        self.g = group.random(G1)
        self.g.initPP()
        self.t = t
        self.max_order = max_order


class Prover:
    def __init__(self, problem, p):
        assert p.degree <= problem.max_order
        self.problem = problem
        self.p = p

    def respond(self, challenge):
        [encrypted_monomials] = challenge
        h = self.p / self.problem.t
        return [
            self.p.evaluate_encrypted(self.problem.g, encrypted_monomials),
            h.evaluate_encrypted(self.problem.g, encrypted_monomials),
        ]


class Verifier:
    def __init__(self, problem):
        self.problem = problem
        self.s = None

    def challenge(self):
        self.s = group.random(ZR)
        monomials = [self.s ** i for i in range(1, self.problem.max_order + 1)]
        encrypted_monomials = [self.problem.g ** s_i for s_i in monomials]
        return [encrypted_monomials]

    def verify(self, response):
        [encrypted_p, encrypted_h] = response
        t_s = self.problem.t.evaluate(self.s)
        assert encrypted_p == encrypted_h ** t_s


if __name__ == "__main__":
    t = Polynomial([-1, 1]) * Polynomial([-2, 1])
    problem = Problem(t, max_order=3)

    p = Polynomial([0, 2, -3, 1])
    prover = Prover(problem, p)
    verifier = Verifier(problem)
    challenge = verifier.challenge()
    response = prover.respond(challenge)
    verifier.verify(response)
    print("p15 example successful.")
