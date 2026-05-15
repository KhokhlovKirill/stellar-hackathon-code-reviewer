"""ChatOps subgraph — handles @secbot slash commands in PR comments."""

from __future__ import annotations

from langgraph.graph import StateGraph, END

from aegis.graph.state import ChatState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def parse_command_node(state: ChatState) -> ChatState:
    """Parse the incoming @secbot command."""
    from aegis.dialog.commands import parse_command

    message = state.get("message", "")
    command, args = parse_command(message)

    log.info("chatops.command", command=command, args=args)

    return {**state, "command": command, "args": args}


async def execute_command_node(state: ChatState) -> ChatState:
    """Execute the parsed command."""
    from aegis.dialog.commands import execute_command

    command = state.get("command", "unknown")
    args = state.get("args", {})
    context = state.get("context", {})

    log.info("chatops.execute", command=command)

    response = await execute_command(command, args, context)

    return {**state, "response": response, "executed": True}


async def format_response_node(state: ChatState) -> ChatState:
    """Format the response for posting back to the PR."""
    response = state.get("response", "")
    command = state.get("command", "")

    formatted = f"**@secbot** › `{command}`\n\n{response}"

    return {**state, "formatted_response": formatted}


def _route_command(state: ChatState) -> str:
    command = state.get("command", "unknown")
    if command == "unknown":
        return "format_response"
    return "execute_command"


def build_chatops_subgraph() -> StateGraph:
    """Build and compile the ChatOps subgraph."""
    builder = StateGraph(ChatState)

    builder.add_node("parse_command", parse_command_node)
    builder.add_node("execute_command", execute_command_node)
    builder.add_node("format_response", format_response_node)

    builder.set_entry_point("parse_command")
    builder.add_conditional_edges(
        "parse_command",
        _route_command,
        {
            "execute_command": "execute_command",
            "format_response": "format_response",
        },
    )
    builder.add_edge("execute_command", "format_response")
    builder.add_edge("format_response", END)

    return builder.compile()


# Compiled subgraph instance (lazy)
_chatops_graph = None


def get_chatops_graph():
    global _chatops_graph
    if _chatops_graph is None:
        _chatops_graph = build_chatops_subgraph()
    return _chatops_graph


async def run_chatops(message: str, context: dict) -> str:
    """Entry point for running the ChatOps subgraph.

    Args:
        message: The raw comment text containing @secbot command.
        context: PR context dict (pr_id, repo, etc.).

    Returns:
        Formatted response string.
    """
    graph = get_chatops_graph()
    initial_state: ChatState = {
        "message": message,
        "context": context,
        "command": None,
        "args": {},
        "response": "",
        "formatted_response": "",
        "executed": False,
    }

    result = await graph.ainvoke(initial_state)
    return result.get("formatted_response", "Command processed.")
