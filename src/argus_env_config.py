import os
import time
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class Provider(Enum):
    NVIDIA = "nvidia"


@dataclass
class ModelConfig:
    alias: str
    provider: Provider
    model_name: str
    api_key_env: str


class ModelTier(Enum):
    LEAD_AGENT = "lead_agent"
    SUBAGENT = "subagent"
    SCORER = "scorer"


class ConfigManager:
    def __init__(self, mode: str = "dev"):
        self.mode = mode

        self.available_models = {
            "nemotron": ModelConfig("nemotron", Provider.NVIDIA, "nvidia/nemotron-3-super-120b-a12b",
                                    "NVIDIA_API_KEY_NEMOTRON"),
            "llama": ModelConfig("llama", Provider.NVIDIA, "meta/llama-3.3-70b-instruct", "NVIDIA_API_KEY_LLAMA"),
            "qwen": ModelConfig("qwen", Provider.NVIDIA, "qwen/qwen3-next-80b-a3b-instruct", "NVIDIA_API_KEY_QWEN"),
            "glm": ModelConfig("glm", Provider.NVIDIA, "z.ai/glm-5.1", "NVIDIA_API_KEY_GLM"),
            "deepseek": ModelConfig("deepseek", Provider.NVIDIA, "deepseek-ai/deepseek-v4-flash",
                                    "NVIDIA_API_KEY_DEEPSEEK"),
            "minimax": ModelConfig("minimax", Provider.NVIDIA, "minimaxai/minimax-m2.7", "NVIDIA_API_KEY_MINIMAX"),
            "scorer": ModelConfig("scorer", Provider.NVIDIA, "meta/llama-3.1-8b-instruct", "NVIDIA_API_KEY_SCORER"),
        }

        self.tier_mapping = {
            ModelTier.LEAD_AGENT: {"dev": "nemotron", "prod": "llama"},
            ModelTier.SUBAGENT: {"dev": "qwen", "prod": "glm"},
            ModelTier.SCORER: {"dev": "scorer", "prod": "scorer"}
        }

    def get_model_config(self, tier: ModelTier) -> ModelConfig:
        alias = self.tier_mapping[tier][self.mode]
        return self.available_models[alias]


class MultiModelClient:
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager

    def execute_chat_completion(self, role: ModelTier, messages: List[Dict[str, Any]],
                                tools: Optional[List[Dict[str, Any]]] = None) -> tuple[str, str, Any]:
        config = self.config_manager.get_model_config(role)
        api_key = os.environ.get(config.api_key_env, "").strip()

        if not api_key:
            raise ValueError(f"API Key missing for {config.alias}. Set {config.api_key_env} in your .env file.")

        kwargs = {"model": config.model_name, "messages": messages}
        if tools:
            kwargs["tools"] = tools

        return self._execute_with_retries(api_key, kwargs, config)

    def _execute_with_retries(self, api_key: str, kwargs: Dict[str, Any], config: ModelConfig, max_attempts: int = 5) -> \
    tuple[str, str, Any]:
        for attempt in range(max_attempts):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=api_key, base_url="https://integrate.api.nvidia.com/v1")

                response = client.chat.completions.create(**kwargs)
                message = response.choices[0].message
                content = message.content or ""
                reasoning = ""

                tool_calls = message.tool_calls if hasattr(message, 'tool_calls') else None
                if not tool_calls and hasattr(message, 'function_call') and message.function_call:
                    tool_calls = [message.function_call]

                return content, reasoning, tool_calls

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {config.alias}: {str(e)}")
                if attempt == max_attempts - 1:
                    raise RuntimeError(f"Execution failed after {max_attempts} attempts. Error: {str(e)}")

                sleep_time = 10 * (attempt + 1)
                logger.info(f"Rate limit or network error hit. Sleeping for {sleep_time} seconds before retrying...")
                time.sleep(sleep_time)