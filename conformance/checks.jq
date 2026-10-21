# jq definitions shared by level1.sh and level2.sh, loaded with `include "checks";`.

# Days from 1970-01-01 to the proleptic Gregorian date $y-$m-$d (the
# days_from_civil algorithm; floor division keeps it right for year 0000).
def days_from_civil($y; $m; $d):
  (if $m <= 2 then $y - 1 else $y end) as $y
  | ($y / 400 | floor) as $era
  | ($y - $era * 400) as $yoe
  | (((153 * (if $m > 2 then $m - 3 else $m + 9 end) + 2) / 5 | floor) + $d - 1) as $doy
  | ($yoe * 365 + ($yoe / 4 | floor) - ($yoe / 100 | floor) + $doy) as $doe
  | $era * 146097 + $doe - 719468;

def days_in_month($y; $m):
  if $m == 2 then (if ($y % 4 == 0 and $y % 100 != 0) or $y % 400 == 0 then 29 else 28 end)
  elif $m == 4 or $m == 6 or $m == 9 or $m == 11 then 30
  else 31 end;

# Epoch seconds of an RFC 3339 timestamp (fractional seconds dropped), or null
# when the input is not one: a day of its month in a year from 0000 to 9999,
# an hour from 00 to 23, a minute and a second from 00 to 59 and a UTC offset
# from 00:00 to 23:59. The seconds are counted here, not by mktime, whose range
# depends on the platform: with jq 1.8.1 on macOS, mktime refuses a year before
# 1900 and 1969-12-31T23:59:59Z (epoch second -1). The pattern ends with \z
# because $ also matches before a final newline.
def rfc3339:
  if type == "string"
     and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])\\z")
  then
    [.[0:4], .[5:7], .[8:10], .[11:13], .[14:16], .[17:19] | tonumber] as [$y, $mo, $d, $h, $mi, $s]
    | if $mo < 1 or $mo > 12 or $d < 1 or $d > days_in_month($y; $mo)
         or $h > 23 or $mi > 59 or $s > 59 then null
      else
        (days_from_civil($y; $mo; $d) * 86400 + $h * 3600 + $mi * 60 + $s) as $t
        | if test("[Zz]$") then $t
          else .[-6:] as $tz
            | (($tz[1:3] | tonumber) * 3600 + ($tz[4:6] | tonumber) * 60) as $offset
            | if $tz[0:1] == "+" then $t - $offset else $t + $offset end
          end
      end
  else null end;

def is_time: rfc3339 != null;

def type_ok($want):
  type as $t | $want == $t or ($want == "integer" and $t == "number" and . == floor);

# True when the input matches schema $s, a node of the schema document $root.
# Implements the JSON Schema keywords the schemas/ files use, and asserts the
# date-time format (Section 8.1: a malformed timestamp rejects the response).
def schema_ok($s; $root):
  if $s | has("$ref") then schema_ok($root | getpath($s["$ref"][2:] | split("/")); $root)
  else
    . as $v | type as $t
    | ($s.type == null or any([$s.type] | flatten[]; . as $want | $v | type_ok($want)))
      and (($s | has("const") | not) or $v == $s.const)
      and ($s.enum == null or any($s.enum[]; . == $v))
      and ($s.anyOf == null or any($s.anyOf[]; . as $a | $v | schema_ok($a; $root)))
      and ($t != "string" or (
        ($s.pattern == null or test($s.pattern))
        and ($s.minLength == null or length >= $s.minLength)
        and ($s.format != "date-time" or is_time)))
      and ($t != "number" or (
        ($s.minimum == null or $v >= $s.minimum)
        and ($s.maximum == null or $v <= $s.maximum)))
      and ($t != "array" or (
        ($s.minItems == null or length >= $s.minItems)
        and ($s.items == null or all(.[]; schema_ok($s.items; $root)))
        and ($s.contains == null or any(.[]; schema_ok($s.contains; $root)))))
      and ($t != "object" or (
        ($s.minProperties == null or length >= $s.minProperties)
        and all(($s.required // [])[]; . as $k | $v | has($k))
        and all(to_entries[]; .key as $k | .value
          | if ($s.properties // {}) | has($k) then schema_ok($s.properties[$k]; $root)
            elif $s.additionalProperties == false then false
            elif ($s.additionalProperties | type) == "object" then schema_ok($s.additionalProperties; $root)
            else true end)))
  end;

# {name: true} for each name in $names the input object carries with a value
# that matches the member's schema in $root, {name: false} otherwise.
def members_ok($root; $names):
  . as $body
  | reduce $names[] as $name ({};
      .[$name] = ($body | type == "object" and has($name)
        and (.[$name] | schema_ok($root.properties[$name]; $root))));

# The outcome of one test, read from the slurped response body: "" when every
# condition f yields (an object of condition -> boolean) is true, otherwise
# what is not met.
def report(f):
  if length == 0 then "no JSON body"
  elif length > 1 then "more than one JSON value"
  else .[0]
    | try (f | to_entries | map(select(.value != true) | .key)
           | if length == 0 then "" else "not met: " + join(", ") end)
      catch "unexpected body shape"
  end;
