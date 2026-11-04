"""Explainable recovery recommendations (slide 11: "Recovery recommendations").

Fixed, reviewable rules on purpose: a language model improvising safety advice during
a disaster is not acceptable. Each list states why it applies. These are prompts for
trained responders and do not replace official instructions from NDMA or local authorities.
"""
from __future__ import annotations

_BY_HAZARD = {
    "flood": ["Move people to higher ground and avoid walking or driving through moving water.",
              "Check drinking water safety and arrange clean water.",
              "Isolate electrical supply in submerged buildings before anyone enters."],
    "earthquake": ["Check damaged buildings before anyone re-enters and expect aftershocks.",
                   "Check for gas leaks and damaged power lines.",
                   "Send search and rescue to collapsed structures first."],
    "cyclone": ["Clear fallen lines and trees from access roads before sending vehicles.",
                "Check shelters for capacity and structural damage.",
                "Restore communication links for affected coastal areas."],
    "landslide": ["Keep people away from the slope and the debris path, more slides can follow.",
                  "Check blocked roads and rivers, a blocked river can flood suddenly."],
    "fire": ["Clear people downwind and keep access routes open for fire crews.",
             "Arrange treatment for smoke exposure and burns."],
    "tsunami": ["Keep people on high ground until authorities give the all-clear.",
                "Expect more than one wave. Do not return to the coast early."],
    "industrial": ["Keep people upwind and outside the exclusion zone.",
                   "Tell responders which chemicals are on site before they enter."],
    "storm": ["Keep people indoors and away from isolated trees and metal structures.",
              "Check for fallen power lines and blocked roads."],
    "heatwave": ["Open cooling points and check on elderly people and outdoor workers.",
                 "Arrange drinking water and treatment for heat illness."],
}
_GENERAL = ["Confirm the location and the number of people affected."]
_SEVERE = ["Prioritise this report for a rescue team.", "Arrange medical aid for the affected area.",
           "Check nearby areas for similar damage."]
_MILD = ["Send an assessment team to confirm the extent of the damage.",
         "Keep monitoring for new reports from this area."]
_NONE = ["No immediate rescue is suggested by this evidence. Keep monitoring."]


def recommend(severity: str, hazard_type: str | None, reliability: float, verification: str) -> dict:
    if severity == "severe_damage":
        actions, why = list(_SEVERE), "The evidence indicates severe damage."
    elif severity == "mild_damage":
        actions, why = list(_MILD), "The evidence indicates mild damage."
    else:
        actions, why = list(_NONE), "The evidence indicates little or no damage."
    if severity != "little_or_no_damage":
        actions += _BY_HAZARD.get(hazard_type or "", [])
    actions += _GENERAL
    caution = None
    if verification != "corroborated":
        caution = "No official alert confirms this report yet. Verify it before committing resources."
    if reliability < 0.5:
        caution = "This assessment has low reliability. A person should look at the evidence first."
    return {"actions": actions, "why": why, "caution": caution}
