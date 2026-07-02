import os
import time
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class Provider(Enum):
    NVIDIA = "nvidia"
    GROQ = "groq"
    MISTRAL = "mistral"
    GEMINI = "gemini"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    GITHUB = "github"


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
            "nemotron_super": ModelConfig("nemotron_super", Provider.NVIDIA, "meta/llama-3.1-70b-instruct",
                                          "NVIDIA_API_KEY"),
            "groq_llama3": ModelConfig("groq_llama3", Provider.GROQ, "llama-3.3-70b-versatile", "GROQ_API_KEY"),
            # Mapped to the massive 500K TPD limit model from your list
            "groq_scorer": ModelConfig("groq_scorer", Provider.GROQ, "llama-3.1-8b-instant", "GROQ_API_KEY"),
            "mistral_large": ModelConfig("mistral_large", Provider.MISTRAL, "mistral-large-latest", "MISTRAL_API_KEY"),
            "gemini_flash": ModelConfig("gemini_flash", Provider.GEMINI, "gemini-2.5-flash", "GEMINI_API_KEY"),
            "openai_gpt4o_mini": ModelConfig("openai_gpt4o_mini", Provider.OPENAI, "gpt-4o-mini", "OPENAI_API_KEY"),
            "openrouter_free": ModelConfig("openrouter_free", Provider.OPENROUTER, "google/gemini-2.0-flash-exp:free",
                                           "OPENROUTER_API_KEY"),
            "github_gpt4o_mini": ModelConfig("github_gpt4o_mini", Provider.GITHUB, "gpt-4o-mini", "GITHUB_TOKEN")
        }

        self.tier_mapping = {
            ModelTier.LEAD_AGENT: {"dev": "nemotron_super", "prod": "github_gpt4o_mini"},
            ModelTier.SUBAGENT: {"dev": "groq_llama3", "prod": "openrouter_free"},
            ModelTier.SCORER: {"dev": "groq_scorer", "prod": "groq_scorer"}
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
                if config.provider == Provider.GEMINI:
                    from openai import OpenAI
                    client = OpenAI(api_key=api_key,
                                    base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
                    return self._process_openai_compatible(client, kwargs)
                elif config.provider in [Provider.OPENAI, Provider.GITHUB, Provider.OPENROUTER, Provider.GROQ,
                                         Provider.NVIDIA, Provider.MISTRAL]:
                    from openai import OpenAI
                    base_url = None
                    if config.provider == Provider.GROQ:
                        base_url = "https://api.groq.com/openai/v1"
                    elif config.provider == Provider.NVIDIA:
                        base_url = "https://integrate.api.nvidia.com/v1"
                    elif config.provider == Provider.OPENROUTER:
                        base_url = "https://openrouter.ai/api/v1"
                    elif config.provider == Provider.GITHUB:
                        base_url = "https://models.inference.ai.azure.com"
                    elif config.provider == Provider.MISTRAL:
                        base_url = "https://api.mistral.ai/v1"

                    client = OpenAI(api_key=api_key, base_url=base_url)
                    return self._process_openai_compatible(client, kwargs)
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {config.alias}: {str(e)}")
                if attempt == max_attempts - 1:
                    raise RuntimeError(f"Execution failed after {max_attempts} attempts. Error: {str(e)}")

                sleep_time = 15 * (attempt + 1)
                logger.info(f"Rate limit or network error hit. Sleeping for {sleep_time} seconds before retrying...")
                time.sleep(sleep_time)

    def _process_openai_compatible(self, client, kwargs):
        response = client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        content = message.content or ""
        reasoning = ""

        tool_calls = message.tool_calls if hasattr(message, 'tool_calls') else None
        if not tool_calls and hasattr(message, 'function_call') and message.function_call:
            tool_calls = [message.function_call]

        return content, reasoning, tool_calls