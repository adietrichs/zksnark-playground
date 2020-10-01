from math import prod

from crypto import G1, ZR, Polynomial, group, pair


class Problem:
    def __init__(self, constraints):
        self.g = group.random(G1)
        self.g.initPP()
        self.num_constraints = len(constraints)
        self.t = Polynomial([1])
        for constraint_num in range(1, self.num_constraints + 1):
            self.t = self.t * Polynomial([-constraint_num, 1])
        self.variable_polynomials = [{}, {}, {}]
        for i, constraint in enumerate(constraints):
            constraint_num = i + 1
            partial_t = self.t / Polynomial([-constraint_num, 1])
            partial_t = partial_t * (1 / partial_t.evaluate(constraint_num))
            for constraint_dict, variable_polynomial_dict in zip(
                constraint, self.variable_polynomials
            ):
                for variable, coefficient in constraint_dict.items():
                    variable_polynomial_dict[variable] = (
                        variable_polynomial_dict.get(variable) or Polynomial([0])
                    ) + partial_t * coefficient
        self.variables = (
            self.variable_polynomials[0].keys()
            | self.variable_polynomials[1].keys()
            | self.variable_polynomials[2].keys()
        )

    def trusted_setup(self):
        s = group.random(ZR)
        alphas = [group.random(ZR), group.random(ZR), group.random(ZR)]
        monomials_short = [s ** i for i in range(1, self.num_constraints + 1)]
        encrypted_monomials_short = [self.g ** s_i for s_i in monomials_short]
        encrypted_monomials = [self.g] + encrypted_monomials_short
        encrypted_shifted_monomials_list = [
            [encrypted_monomial ** alpha for encrypted_monomial in encrypted_monomials]
            for alpha in alphas
        ]
        encrypted_variable_polynomials = [
            {
                variable: polynomial.evaluate_encrypted(
                    self.g, encrypted_monomials_short
                )
                for variable, polynomial in variable_polynomial_dict.items()
            }
            for variable_polynomial_dict in self.variable_polynomials
        ]
        encrypted_shifted_variable_polynomials = [
            {
                variable: polynomial.evaluate_encrypted(
                    encrypted_shifted_monomials[0], encrypted_shifted_monomials[1:]
                )
                for variable, polynomial in variable_polynomial_dict.items()
            }
            for variable_polynomial_dict, encrypted_shifted_monomials in zip(
                self.variable_polynomials, encrypted_shifted_monomials_list
            )
        ]
        g_t = self.g ** self.t.evaluate(s)
        proving_key = [
            encrypted_monomials_short,
            encrypted_variable_polynomials,
            encrypted_shifted_variable_polynomials,
        ]
        verification_key = [
            [
                encrypted_shifted_monomials[0]
                for encrypted_shifted_monomials in encrypted_shifted_monomials_list
            ],
            g_t,
        ]
        return [proving_key, verification_key]


class Prover:
    def __init__(self, problem, proving_key):
        self.problem = problem
        (
            self.encrypted_monomials_short,
            self.encrypted_variable_polynomials,
            self.encrypted_shifted_variable_polynomials,
        ) = proving_key

    def prove(self, variable_assignments):
        assert self.problem.variables == variable_assignments.keys()
        L, R, O = [
            sum(
                [
                    polynomial * variable_assignments[variable]
                    for variable, polynomial in variable_polynomial_dict.items()
                ]
            )
            for variable_polynomial_dict in self.problem.variable_polynomials
        ]
        h = (L * R - O) / self.problem.t
        g_L, g_R, g_O = [
            prod(
                [
                    encrypted_polynomial ** variable_assignments[variable]
                    for variable, encrypted_polynomial in encrypted_variable_polynomial_dict.items()
                ]
            )
            for encrypted_variable_polynomial_dict in self.encrypted_variable_polynomials
        ]
        shifted_g_L, shifted_g_R, shifted_g_O = [
            prod(
                [
                    encrypted_shifted_polynomial ** variable_assignments[variable]
                    for variable, encrypted_shifted_polynomial in encrypted_shifted_variable_polynomial_dict.items()
                ]
            )
            for encrypted_shifted_variable_polynomial_dict in self.encrypted_shifted_variable_polynomials
        ]
        g_h = h.evaluate_encrypted(self.problem.g, self.encrypted_monomials_short)
        return [g_L, g_R, g_O, shifted_g_L, shifted_g_R, shifted_g_O, g_h]


class Verifier:
    def __init__(self, problem, verification_key):
        self.problem = problem
        self.encrypted_alphas, self.g_t = verification_key

    def verify(self, proof):
        [g_L, g_R, g_O, g_L_prime, g_R_prime, g_O_prime, g_h] = proof
        assert pair(g_L_prime, self.problem.g) == pair(g_L, self.encrypted_alphas[0])
        assert pair(g_R_prime, self.problem.g) == pair(g_R, self.encrypted_alphas[1])
        assert pair(g_O_prime, self.problem.g) == pair(g_O, self.encrypted_alphas[2])
        assert pair(g_L, g_R) == pair(self.g_t, g_h) * pair(g_O, self.problem.g)


if __name__ == "__main__":
    constraints = [
        [{"a": 1}, {"b": 1}, {"m": 1}],
        [{"w": 1}, {"m": 1, "a": -1, "b": -1}, {"v": 1, "a": -1, "b": -1}],
        [{"w": 1}, {"w": 1}, {"w": 1}],
    ]
    problem = Problem(constraints)
    proving_key, verification_key = problem.trusted_setup()
    prover = Prover(problem, proving_key)
    verifier = Verifier(problem, verification_key)

    proof = prover.prove({"a": 5, "b": 7, "m": 35, "v": 12, "w": 0})
    verifier.verify(proof)
    print("p50 example successful.")
