Feature: A machine's resident agent takes prompts, and a fork replays them

  `mvmctl machine prompt` delivers one prompt to the program the image bakes
  at /etc/mvm/entrypoint and records it: journaled under an agent session,
  encrypted for replay, chain-audited by digest, and captured as a
  session-bound vm_full step checkpoint. `mvmctl agent-session replay`
  fork-boots the session's base checkpoint and re-delivers the recorded
  prompts to the fork.

  The example agent answers with a turn count it keeps in the guest. That is
  what makes the replay checkable from outside: a fork that was replayed onto
  answers its next prompt as turn three, while a fork that received nothing,
  or received it onto the wrong state, answers with some other turn.

  @live @snapshot
  Scenario: recorded prompts replay onto a fork of the session's base
    Given the prompt agent machine is running
    When I run mvmctl against the prompt agent with "machine prompt bdd-prompt first"
    Then the command exits with code 0
    And the output contains "turn 1: first"
    When I run mvmctl against the prompt agent with "machine prompt bdd-prompt second"
    Then the command exits with code 0
    And the output contains "turn 2: second"
    When I run mvmctl against the prompt agent with "agent-session replay bdd-prompt --as bdd-prompt-replay"
    Then the command exits with code 0
    And the prompt agent reports "replayed 2 prompt(s)"
    When I run mvmctl against the prompt agent with "machine prompt bdd-prompt-replay third --no-step-checkpoint"
    Then the command exits with code 0
    And the output contains "turn 3: third"
    Then the prompt agent machines are removed
