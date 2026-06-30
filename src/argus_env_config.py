import os
import time
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple, Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


class Provider(Enum):
    NVIDIA = "nvidia"
    GROQ = "groq"
    MISTRAL = "mistral"
    GEMINI = "gemini"


class ModelTier(Enum):
    LEAD_AGENT = "lead_agent"
    SUBAGENT = "subagent"
    SCORER = "scorer"


@dataclass
class ModelConfig:
    provider: Provider
    model_name: str
    base_url: str
    api_key_env: str
    requires_thinking: bool = False
    temperature: float = 0.7
    max_tokens: int = 4096
    top_p: float = 0.95


@dataclass
class EnvironmentState:
    mode: str = "dev"
    max_retries: int = 3
    retry_delay: int = 2


class ConfigManager:
    def __init__(self, mode: str = "dev"):
        self.state = EnvironmentState(mode=mode)
        self.available_models: Dict[str, ModelConfig] = self._initialize_available_models()
        self.tier_mapping: Dict[ModelTier, Dict[str, str]] = self._initialize_tier_mappings()

    def _initialize_available_models(self) -> Dict[str, ModelConfig]:
        return {
            "nemotron_super": ModelConfig(
                provider=Provider.NVIDIA,
                model_name="nvidia/nemotron-3-super-120b-a12b",
                base_url="https://integrate.api.nvidia.com/v1",
                api_key_env="NVIDIA_API_KEY",
                requires_thinking=True
            ),
            "nemotron_ultra": ModelConfig(
                provider=Provider.NVIDIA,
                model_name="nvidia/nemotron-3-ultra-550b-a55b",
                base_url="https://integrate.api.nvidia.com/v1",
                api_key_env="NVIDIA_API_KEY",
                requires_thinking=True
            ),
            "groq_llama3": ModelConfig(
                provider=Provider.GROQ,
                model_name="llama-3.3-70b-versatile",
                base_url="https://api.groq.com/openai/v1",
                api_key_env="GROQ_API_KEY"
            ),
            "mistral_large": ModelConfig(
                provider=Provider.MISTRAL,
                model_name="mistral-large-latest",
                base_url="https://api.mistral.ai/v1",
                api_key_env="MISTRAL_API_KEY"
            ),
            "gemini_flash": ModelConfig(
                provider=Provider.GEMINI,
                model_name="gemini-2.5-flash",
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key_env="GEMINI_API_KEY"
            )
        }

    def _initialize_tier_mappings(self) -> Dict[ModelTier, Dict[str, str]]:
        return {
            ModelTier.LEAD_AGENT: {
                "dev": "nemotron_super",
                "prod": "nemotron_ultra"
            },
            ModelTier.SUBAGENT: {
                "dev": "nemotron_super",
                "prod": "nemotron_super"
            },
            ModelTier.SCORER: {
                "dev": "nemotron_super",
                "prod": "nemotron_ultra"
            }
        }

    def get_config_for_tier(self, tier: ModelTier) -> ModelConfig:
        alias = self.tier_mapping.get(tier).get(self.state.mode)
        return self.available_models.get(alias)


class MultiModelClient:
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.clients: Dict[str, OpenAI] = {}
        self._initialize_clients()

    def _initialize_clients(self) -> None:
        for alias, config in self.config_manager.available_models.items():
            api_key = os.environ.get(config.api_key_env, "").strip()
            if api_key:
                self.clients[alias] = OpenAI(base_url=config.base_url, api_key=api_key)

    def execute_chat_completion(self, role: ModelTier, messages: List[Dict[str, Any]],
                                tools: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, str, Any]:
        config = self.config_manager.get_config_for_tier(role)
        alias = self.config_manager.tier_mapping.get(role).get(self.config_manager.state.mode)
        client = self.clients.get(alias)

        if not client:
            raise ValueError(f"Client for alias {alias} not initialized. Check {config.api_key_env}.")

        kwargs = self._build_request_kwargs(config, messages, tools)
        return self._execute_with_retries(client, kwargs, config)

    def _build_request_kwargs(self, config: ModelConfig, messages: List[Dict[str, Any]],
                              tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        kwargs = {
            "model": config.model_name,
            "messages": messages,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "max_tokens": config.max_tokens
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if config.requires_thinking and config.provider == Provider.NVIDIA:
            kwargs["extra_body"] = {
                "chat_template_kwargs": {"enable_thinking": True},
                "reasoning_budget": config.max_tokens
            }
            kwargs["stream"] = True

        return kwargs

    def _execute_with_retries(self, client: OpenAI, kwargs: Dict[str, Any], config: ModelConfig) -> Tuple[
        str, str, Any]:
        attempts = 0
        max_attempts = self.config_manager.state.max_retries
        delay = self.config_manager.state.retry_delay

        while attempts < max_attempts:
            try:
                if kwargs.get("stream", False):
                    return self._process_streaming_response(client, kwargs)
                else:
                    return self._process_standard_response(client, kwargs)
            except Exception as e:
                attempts += 1
                if attempts >= max_attempts:
                    raise RuntimeError(f"Execution failed after {max_attempts} attempts. Error: {str(e)}")
                time.sleep(delay * attempts)

        return "", "", None

    def _process_streaming_response(self, client: OpenAI, kwargs: Dict[str, Any]) -> Tuple[str, str, Any]:
        completion = client.chat.completions.create(**kwargs)
        final_content = []
        reasoning_content = []
        tool_calls_accumulator = {}

        for chunk in completion:
            if not chunk.choices:
                continue

            delta = chunk.choices[0].delta

            reasoning = getattr(delta, "reasoning_content", None)
            if reasoning:
                reasoning_content.append(reasoning)

            if delta.content is not None:
                final_content.append(delta.content)

            if delta.tool_calls:
                self._accumulate_tool_calls(tool_calls_accumulator, delta.tool_calls)

        assembled_content = "".join(final_content)
        assembled_reasoning = "".join(reasoning_content)
        assembled_tools = self._format_accumulated_tools(tool_calls_accumulator)

        return assembled_content, assembled_reasoning, assembled_tools

    def _process_standard_response(self, client: OpenAI, kwargs: Dict[str, Any]) -> Tuple[str, str, Any]:
        response = client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        content = message.content if message.content else ""
        tool_calls = message.tool_calls if hasattr(message, "tool_calls") else None
        return content, "", tool_calls

    def _accumulate_tool_calls(self, accumulator: Dict[int, Any], tool_calls: List[Any]) -> None:
        for tool_call in tool_calls:
            idx = tool_call.index
            if idx not in accumulator:
                accumulator[idx] = {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name if tool_call.function.name else "",
                        "arguments": ""
                    }
                }
            if tool_call.function.arguments:
                accumulator[idx]["function"]["arguments"] += tool_call.function.arguments

    def _format_accumulated_tools(self, accumulator: Dict[int, Any]) -> Optional[List[Dict[str, Any]]]:
        if not accumulator:
            return None
        formatted_list = []
        for idx in sorted(accumulator.keys()):
            formatted_list.append(accumulator[idx])
        return formatted_list