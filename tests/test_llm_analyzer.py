import unittest
from unittest.mock import patch, MagicMock

# Import the module to be tested
from src.engines.llm_analyzer import run_llm_analysis, PROMPTS

class TestLLMAnalyzer(unittest.TestCase):

    @patch("src.engines.llm_analyzer.requests.post")
    def test_prompt_dispatch_unit_test(self, mock_post):
        # Set up the mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"urgency_score": 5, "legitimacy_score": 5, "grammar_score": 5, "coherence_score": 5, "social_engineering_tactics": [], "detected_intent": "unknown", "threat_probability": 0.5, "reasoning": "Test reasoning."}'
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        # Call the function with channel="sms"
        run_llm_analysis(text="fake_text", channel="sms")

        # Assert that requests.post was called
        mock_post.assert_called_once()

        # Extract the payload passed to requests.post
        call_args = mock_post.call_args
        kwargs = call_args[1]
        payload = kwargs.get("json")

        # Assert that payload is not None
        self.assertIsNotNone(payload)

        # Find the system role message in the payload
        messages = payload.get("messages", [])
        system_message = None
        for msg in messages:
            if msg.get("role") == "system":
                system_message = msg
                break
        
        # Assert that system_message exists and its content is the sms prompt
        self.assertIsNotNone(system_message)
        self.assertEqual(system_message.get("content"), PROMPTS["sms"])
        self.assertIn("SMISHING", system_message.get("content"))

if __name__ == "__main__":
    unittest.main()
