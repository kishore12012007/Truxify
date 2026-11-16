
"""Unit tests for causal impact step-change recovery."""

import unittest

try:
    import numpy as np
    from causal_inference import CausalImpact as CausalImpactMeasurer

    HAVE_DEPS = True
    DEPENDENCY_ERROR = ""

except ImportError as exc:
    np = None
    CausalImpactMeasurer = None
    HAVE_DEPS = False
    DEPENDENCY_ERROR = str(exc)


@unittest.skipUnless(
    HAVE_DEPS,
    f"Required dependencies are unavailable: {DEPENDENCY_ERROR}",
)
class TestCausalImpactStepRecovery(unittest.TestCase):

    def setUp(self):
        self.measurer = CausalImpactMeasurer()
        self.rng = np.random.default_rng(0)

    def test_recovers_injected_step_on_post_period(self):
        """Verify that a positive step intervention produces a positive effect."""

        # Generate baseline data.
        baseline = 10.0 + self.rng.normal(0, 0.1, 30)

        # Generate post-intervention data with a +5 step.
        step = 5.0
        post = (10.0 + step) + self.rng.normal(0, 0.1, 30)

        pre_data = baseline.astype(np.float64)
        post_data = post.astype(np.float64)

        # Validate generated input data.
        self.assertEqual(pre_data.shape, (30,))
        self.assertEqual(post_data.shape, (30,))

        self.assertTrue(np.all(np.isfinite(pre_data)))
        self.assertTrue(np.all(np.isfinite(post_data)))

        # Measure causal impact.
        result = self.measurer.measure_impact(
            pre_data,
            post_data,
        )

        # Validate the returned result.
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)

        self.assertIn("absolute_effect", result)

        absolute_effect = result["absolute_effect"]

        # Check that the effect is numeric.
        self.assertIsInstance(
            absolute_effect,
            (int, float, np.integer, np.floating),
        )

        self.assertFalse(
            isinstance(absolute_effect, (bool, np.bool_)),
            "absolute_effect must not be a boolean",
        )

        # Check that the result is finite.
        self.assertTrue(
            np.isfinite(absolute_effect),
            "Estimated effect should be finite",
        )

        # Check the direction of the effect.
        self.assertGreater(
            absolute_effect,
            0,
            "Estimated effect should be positive",
        )

        # Check recovery accuracy.
        self.assertAlmostEqual(
            float(absolute_effect),
            step,
            delta=0.5,
            msg="Estimated effect should be close to the injected +5 step",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
