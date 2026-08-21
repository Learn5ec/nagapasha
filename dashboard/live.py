"""WebSocket endpoint for live run updates.

Handles bidirectional communication:
- Push: stat updates and findings to connected client
- Pull: pause/resume/kill commands from client
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

from dashboard import active_runs, event_bus

logger = logging.getLogger(__name__)


async def websocket_endpoint(
    websocket: WebSocket,
    engagement_id: str,
) -> None:
    """WebSocket endpoint for live run updates.

    On connect:
    - Accept connection
    - Subscribe to events for this engagement
    - Push current stats and findings

    On message:
    - Parse action (pause/resume/kill)
    - Execute action on ActiveRuns

    On disconnect:
    - Unsubscribe from events
    """
    await websocket.accept()

    # Register callback for this engagement
    async def on_event(data: dict) -> None:
        """Push data to the WebSocket client."""
        try:
            await websocket.send_json(data)
        except Exception:
            logger.warning(f"Failed to push WebSocket data for {engagement_id}")

    event_bus.subscribe(f"engagement:{engagement_id}", on_event)

    # Push initial state
    run = active_runs.get(engagement_id)
    if run:
        await websocket.send_json({
            "type": "status",
            "data": run.to_dict(),
        })

        # Push findings if any
        for finding in run.findings:
            await websocket.send_json({
                "type": "finding",
                "data": finding,
            })
    else:
        # Send empty status for engagements with no active run
        await websocket.send_json({
            "type": "status",
            "data": {
                "engagement_id": engagement_id,
                "status": "not_found",
                "total_fired": 0,
                "payload_count": 0,
                "hits": 0,
                "near_misses": 0,
                "no_diff": 0,
                "progress": 0,
            },
        })

    try:
        while True:
            # Wait for messages
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON",
                })
                continue

            action = message.get("action")
            if not action:
                continue

            # Execute action
            success = False
            if action == "pause":
                success = active_runs.pause(engagement_id)
            elif action == "resume":
                success = active_runs.resume(engagement_id)
            elif action == "kill":
                success = active_runs.kill(engagement_id)
                # On kill, also update the store
                if success:
                    from nagapasha.db.schema import EngagementStore
                    with EngagementStore() as store:
                        store.update_engagement_status(engagement_id, "killed")

            await websocket.send_json({
                "type": "action_result",
                "action": action,
                "success": success,
            })

    except WebSocketDisconnect:
        pass
    finally:
        # Clean up
        event_bus.unsubscribe(f"engagement:{engagement_id}", on_event)
