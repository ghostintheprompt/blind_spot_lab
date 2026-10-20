"""The remaining blind spot, kept on purpose. The sink is rebound to a
local variable at runtime. Static import resolution cannot see this; it
is a value-tracking problem, the same limitation that lets a cross-
boundary taint slip. The reviewer returns PASS, and the test asserts
that miss rather than hiding it."""
import os


def ping(host):
    run = os.system                # sink bound to a variable at runtime
    run("ping -c 1 " + host)       # real injection the AST layer does not follow
