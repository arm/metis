# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import FunctionParameter
from metis.engine.codegraph import NullCondition
from metis.engine.codegraph import NullFact
from metis.engine.nodes.reachability.state import FactAtom
from metis.engine.nodes.reachability.state import FactLiteral
from metis.engine.nodes.reachability.state import FunctionContract
from metis.engine.nodes.reachability.state import GuardedTransfer
from metis.engine.nodes.reachability.state import ParameterSubject
from metis.engine.nodes.reachability.state import ReturnSubject
from metis.engine.nodes.reachability.state import StateEffect
from metis.engine.nodes.reachability.state import (
    callsite_has_deterministic_nonnull_return,
)


def _nonnull_call() -> tuple[FunctionNode, CallSite, FactLiteral, StateEffect]:
    argument = CodeExpression(
        "context",
        1,
        10,
        17,
        identifiers=("context",),
        direct_identifier="context",
    )
    callsite = CallSite(
        "producer",
        1,
        1,
        start_byte=20,
        end_byte=30,
        target_ids=("state.c::producer",),
        arguments=(argument,),
        must_conditions=(
            ControlCondition(
                CodeExpression(
                    "context != NULL",
                    1,
                    0,
                    15,
                    identifiers=("context",),
                ),
                True,
                NullCondition(
                    when_true=(NullFact(argument, False),),
                    when_false=(NullFact(argument, True),),
                ),
            ),
        ),
    )
    owner = FunctionNode(
        unique_name="state.c::root",
        file_path="state.c",
        name="root",
        line_number=1,
        end_line=1,
        call_sites=[callsite],
        parameters=(FunctionParameter("context", "void *"),),
        parameter_count=1,
    )
    requirement = FactLiteral(
        FactAtom(ParameterSubject("state.c::producer", 0), "null"),
        "negated",
        1,
        "derived",
    )
    effect = StateEffect(
        "negate",
        FactAtom(ReturnSubject("state.c::producer"), "null"),
        "derived",
        1,
    )
    return owner, callsite, requirement, effect


def _contract(
    requirement: FactLiteral,
    effect: StateEffect,
) -> dict[str, FunctionContract]:
    return {
        "state.c::producer": FunctionContract(
            "state.c::producer",
            normal_return_transfers=(
                GuardedTransfer(requirements=(requirement,), effects=(effect,)),
            ),
        )
    }


def test_callsite_nonnull_proof_requires_deterministic_syntax_facts() -> None:
    owner, callsite, requirement, effect = _nonnull_call()

    assert callsite_has_deterministic_nonnull_return(
        owner,
        callsite,
        _contract(requirement, effect),
    )
    assert not callsite_has_deterministic_nonnull_return(
        owner,
        callsite,
        _contract(replace(requirement, origin="hypothesis"), effect),
    )
    assert not callsite_has_deterministic_nonnull_return(
        owner,
        callsite,
        _contract(requirement, replace(effect, origin="hypothesis")),
    )
    assert not callsite_has_deterministic_nonnull_return(
        owner,
        replace(callsite, target_ids=("state.c::producer", "state.c::other")),
        _contract(requirement, effect),
    )
