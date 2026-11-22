# Collector v1 receiver refusal profile

The fixture receiver returns a bounded HTTP 422 body containing only `code` when
a JSON request fails wire validation. The whole batch remains uncommitted. A
sender that sees `invalid_row` checks its stored observation against the pinned
admission rules before recording any local loss. Each supplemental vector
contains the exact request text and expected code. [Supplemental refusal vectors](../tests/fixtures/collector_v1_refusals.json)

## Row wrappers

In a v1 batch with otherwise valid framing, a row object with a valid
`ordinal` and an absent `observation` produces `invalid_row`. Supplying
`null`, a wrong type or invalid observation fields also produces
`invalid_row`. A missing or invalid ordinal, an extra wrapper field, or a row
that is itself null or another non-object produces `invalid_envelope`.
Batch integrity errors such as repeated ordinals or repeated identifiable
source keys take precedence over observation validation.

## Number tokens

Emit decimal integer tokens for every integer field. Each field has its own
lower and upper bounds. The largest allowed counter or ordinal is
9,007,199,254,740,991. In the v1 batch a decoded out-of-range
`source.byte_position` gets `invalid_row`. An out-of-range `ordinal` gets
`invalid_envelope`. A heartbeat with an invalid counter gets
`invalid_envelope`.

The supplemental numeric cases characterize the CPython JSON decoder with its
default 4,300-digit integer conversion limit. A 4,300-digit positive integer
in `source.byte_position` reaches the observation range check. At 4,301 digits
the decoder fails before it can locate a bad observation and the receiver
returns `invalid_envelope`. Changing the interpreter limit can change that
refusal code. The request byte cap still applies.

The decoder treats fraction and exponent syntax as binary floating point.
Both `1e0` and `1e400` in `source.byte_position` reach the strict field
validator and produce `invalid_row`, including when the conversion has
overflowed to infinity. The same tokens in an ordinal produce
`invalid_envelope`. Literal `NaN`, `Infinity` and `-Infinity` fail during
framing anywhere in the request. These are receiver-specific refusal
classifications. An alternative decoder needs its own qualification against
these vectors.

## Source time

On the wire, `source_at` uses valid Gregorian dates in years 0001–9999,
UTC `Z`, hours 00–23, minutes and seconds 00–59, and an optional fraction of
one to six decimal places. The ordinary-seconds subset excludes the leap
second `2016-12-31T23:59:60Z`, which yields `invalid_row`. For that same
native timestamp the fixture projector omits the optional field. Accepted wire
timestamps retain their exact spelling, including trailing fractional zeros,
in the canonical observation digest.
