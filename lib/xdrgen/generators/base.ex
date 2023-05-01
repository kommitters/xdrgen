__all__ = [
  "Int",
  "UInt",
  "Float",
  "DoubleFloat",
  "HyperInt",
  "HyperUInt",
  "Bool",
  "String",
  "FixedOpaque ",
  "VariableOpaque",
]

defmodule Int do
  @behaviour XDR.Declaration

  @type t :: %__MODULE__{datum: integer()}

  defstruct [:datum]

  @spec new(int :: integer()) :: t()
  def new(int), do: %__MODULE__{datum: int}

  @impl true
  def encode_xdr(%__MODULE__{datum: int}) do
    XDR.HyperInt.encode_xdr(%XDR.HyperInt{datum: int})
  end

  @impl true
  def encode_xdr!(%__MODULE__{datum: int}) do
    XDR.HyperInt.encode_xdr!(%XDR.HyperInt{datum: int})
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.HyperInt.decode_xdr(bytes) do
      {:ok, {%XDR.HyperInt{datum: int}, rest}} -> {:ok, {new(int), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.HyperInt{datum: int}, rest} = XDR.HyperInt.decode_xdr!(bytes)
    {new(int), rest}
  end
end

defmodule UInt do
  @behaviour XDR.Declaration

  @type t :: %__MODULE__{datum: non_neg_integer()}

  defstruct [:datum]

  @spec new(uint :: non_neg_integer()) :: t()
  def new(uint), do: %__MODULE__{datum: uint}

  @impl true
  def encode_xdr(%__MODULE__{datum: uint}) do
    XDR.HyperUInt.encode_xdr(%XDR.HyperUInt{datum: uint})
  end

  @impl true
  def encode_xdr!(%__MODULE__{datum: uint}) do
    XDR.HyperUInt.encode_xdr!(%XDR.HyperUInt{datum: uint})
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.HyperUInt.decode_xdr(bytes) do
      {:ok, {%XDR.HyperUInt{datum: uint}, rest}} -> {:ok, {new(uint), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.HyperUInt{datum: uint}, rest} = XDR.HyperUInt.decode_xdr!(bytes)
    {new(uint), rest}
  end
end

defmodule Float do
  @behaviour XDR.Declaration

  alias XDR.FloatError

  defstruct [:float]

  defguard valid_float?(value) when is_float(value) or is_integer(value)

  @type float_number :: integer() | float() | binary()

  @typedoc """
  `XDR.Float` structure type specification.
  """
  @type t :: %XDR.Float{float: float_number()}

  @doc """
  Create a new `XDR.Float` structure with the `float` passed.
  """
  @spec new(float :: float_number()) :: t()
  def new(float), do: %XDR.Float{float: float}

  @doc """
  Encode a `XDR.Float` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%XDR.Float{float: float}) when not valid_float?(float),
    do: {:error, :not_number}

  def encode_xdr(%XDR.Float{float: float}), do: {:ok, <<float::big-signed-float-size(32)>>}

  @doc """
  Encode a `XDR.Float` structure into a XDR format.
  If the `float` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(float) do
    case encode_xdr(float) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(FloatError, reason)
    end
  end

  @doc """
  Decode the Floating-Point in XDR format to a `XDR.Float` structure.
  """
  @impl true
  def decode_xdr(bytes, float \\ nil)

  def decode_xdr(bytes, _float) when not is_binary(bytes),
    do: {:error, :not_binary}

  def decode_xdr(<<float::big-signed-float-size(32), rest::binary>>, _float),
    do: {:ok, {new(float), rest}}

  @doc """
  Decode the Floating-Point in XDR format to a `XDR.Float` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, float \\ nil)

  def decode_xdr!(bytes, float) do
    case decode_xdr(bytes, float) do
      {:ok, result} -> result
      {:error, reason} -> raise(FloatError, reason)
    end
  end
end

defmodule DoubleFloat do
  @behaviour XDR.Declaration

  alias XDR.DoubleFloatError

  defstruct [:float]

  defguard valid_float?(value) when is_float(value) or is_integer(value)

  @type float_number :: integer() | float() | binary()

  @typedoc """
  `XDR.DoubleFloat` struct type specification.
  """
  @type t :: %XDR.DoubleFloat{float: float_number()}

  @doc """
  Create a new `XDR.DoubleFloat` structure from the `float` passed.
  """
  @spec new(float :: float_number()) :: t()
  def new(float), do: %XDR.DoubleFloat{float: float}

  @doc """
  Encode a `XDR.DoubleFloat` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%XDR.DoubleFloat{float: float}) when not valid_float?(float),
    do: {:error, :not_number}

  def encode_xdr(%XDR.DoubleFloat{float: float}), do: {:ok, <<float::big-signed-float-size(64)>>}

  @doc """
  Encode a `XDR.DoubleFloat` structure into a XDR format.
  If the `double_float` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(double_float) do
    case encode_xdr(double_float) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(DoubleFloatError, reason)
    end
  end

  @doc """
  Decode the Double-Precision Floating-Point in XDR format to a `XDR.DoubleFloat` structure.
  """
  @impl true
  def decode_xdr(bytes, double_float \\ nil)
  def decode_xdr(bytes, _double_float) when not is_binary(bytes), do: {:error, :not_binary}

  def decode_xdr(bytes, _double_float) do
    <<float::big-signed-float-size(64), rest::binary>> = bytes

    decoded_float = new(float)

    {:ok, {decoded_float, rest}}
  end

  @doc """
  Decode the Double-Precision Floating-Point in XDR format to a `XDR.DoubleFloat` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, double_float \\ nil)

  def decode_xdr!(bytes, double_float) do
    case decode_xdr(bytes, double_float) do
      {:ok, result} -> result
      {:error, reason} -> raise(DoubleFloatError, reason)
    end
  end
end

defmodule HyperInt do
  @behaviour XDR.Declaration

  alias XDR.HyperIntError

  defstruct [:datum]

  @type datum :: integer() | binary()

  @typedoc """
  `XDR.HyperInt` structure type specification.
  """
  @type t :: %XDR.HyperInt{datum: datum()}

  @doc """
  Create a new `XDR.HyperInt` structure with the `datum` passed.
  """
  @spec new(datum :: datum()) :: t()
  def new(datum), do: %XDR.HyperInt{datum: datum}

  @doc """
  Encode a `XDR.HyperInt` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%XDR.HyperInt{datum: datum}) when not is_integer(datum),
    do: {:error, :not_integer}

  def encode_xdr(%XDR.HyperInt{datum: datum}) when datum > 9_223_372_036_854_775_807,
    do: {:error, :exceed_upper_limit}

  def encode_xdr(%XDR.HyperInt{datum: datum}) when datum < -9_223_372_036_854_775_808,
    do: {:error, :exceed_lower_limit}

  def encode_xdr(%XDR.HyperInt{datum: datum}), do: {:ok, <<datum::big-signed-integer-size(64)>>}

  @doc """
  Encode a `XDR.HyperInt` structure into a XDR format.
  If the `h_int` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(h_int) do
    case encode_xdr(h_int) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(HyperIntError, reason)
    end
  end

  @doc """
  Decode the Hyper Integer in XDR format to a `XDR.HyperInt` structure.
  """
  @impl true
  def decode_xdr(bytes, h_int \\ nil)

  def decode_xdr(bytes, _h_int) when not is_binary(bytes),
    do: {:error, :not_binary}

  def decode_xdr(<<hyper_int::big-signed-integer-size(64), rest::binary>>, _h_int),
    do: {:ok, {new(hyper_int), rest}}

  @doc """
  Decode the Hyper Integer in XDR format to a `XDR.HyperInt` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, h_int \\ nil)

  def decode_xdr!(bytes, h_int) do
    case decode_xdr(bytes, h_int) do
      {:ok, result} -> result
      {:error, reason} -> raise(HyperIntError, reason)
    end
  end
end

defmodule HyperUInt do
  @behaviour XDR.Declaration

  alias XDR.HyperUIntError

  defstruct [:datum]

  @type datum :: integer() | binary()

  @typedoc """
  `XDR.HyperUInt` structure type specification.
  """
  @type t :: %XDR.HyperUInt{datum: datum()}

  @doc """
  Create a new `XDR.HyperUInt` structure with the `opaque` and `length` passed.
  """
  @spec new(datum :: datum()) :: t()
  def new(datum), do: %XDR.HyperUInt{datum: datum}

  @doc """
  Encode a `XDR.HyperUInt` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%XDR.HyperUInt{datum: datum}) when not is_integer(datum),
    do: {:error, :not_integer}

  def encode_xdr(%XDR.HyperUInt{datum: datum}) when datum > 18_446_744_073_709_551_615,
    do: {:error, :exceed_upper_limit}

  def encode_xdr(%XDR.HyperUInt{datum: datum}) when datum < 0,
    do: {:error, :exceed_lower_limit}

  def encode_xdr(%XDR.HyperUInt{datum: datum}),
    do: {:ok, <<datum::big-unsigned-integer-size(64)>>}

  @doc """
  Encode a `XDR.HyperUInt` structure into a XDR format.
  If the `h_uint` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(h_uint) do
    case encode_xdr(h_uint) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(HyperUIntError, reason)
    end
  end

  @doc """
  Decode the Unsigned Hyper Integer in XDR format to a `XDR.HyperUInt` structure.
  """
  @impl true
  def decode_xdr(bytes, h_uint \\ nil)

  def decode_xdr(bytes, _h_uint) when not is_binary(bytes),
    do: {:error, :not_binary}

  def decode_xdr(<<hyper_uint::big-unsigned-integer-size(64), rest::binary>>, _h_uint),
    do: {:ok, {new(hyper_uint), rest}}

  @doc """
  Decode the Unsigned Hyper Integer in XDR format to a `XDR.HyperUInt` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, h_uint \\ nil)

  def decode_xdr!(bytes, h_uint) do
    case decode_xdr(bytes, h_uint) do
      {:ok, result} -> result
      {:error, reason} -> raise(HyperUIntError, reason)
    end
  end
end

defmodule Bool do
  @behaviour XDR.Declaration

  @type t :: %__MODULE__{value: boolean()}

  defstruct [:value]

  @spec new(value :: boolean()) :: t()
  def new(val), do: %__MODULE__{value: val}

  @impl true
  def encode_xdr(%__MODULE__{value: value}) do
    XDR.Bool.encode_xdr(%XDR.Bool{identifier: value})
  end

  @impl true
  def encode_xdr!(%__MODULE__{value: value}) do
    XDR.Bool.encode_xdr!(%XDR.Bool{identifier: value})
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.Bool.decode_xdr(bytes) do
      {:ok, {%XDR.Bool{identifier: val}, rest}} -> {:ok, {new(val), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.Bool{identifier: val}, rest} = XDR.Bool.decode_xdr!(bytes)
    {new(val), rest}
  end
end

defmodule String do
  @behaviour XDR.Declaration

  alias XDR.{VariableOpaque, StringError}

  defstruct [:string, :max_length]

  @typedoc """
  `XDR.String` structure type specification.
  """
  @type t :: %XDR.String{string: binary(), max_length: integer()}

  @doc """
  Create a new `XDR.String` structure with the `opaque` and `length` passed.
  """
  @spec new(string :: bitstring(), max_length :: integer()) :: t()
  def new(string, max_length \\ 4_294_967_295)
  def new(string, max_length), do: %XDR.String{string: string, max_length: max_length}

  @doc """
  Encode a `XDR.String` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%{string: string}) when not is_bitstring(string),
    do: {:error, :not_bitstring}

  def encode_xdr(%{string: string, max_length: max_length}) when byte_size(string) > max_length,
    do: {:error, :invalid_length}

  def encode_xdr(%{string: string, max_length: max_length}) do
    variable_opaque =
      string
      |> VariableOpaque.new(max_length)
      |> VariableOpaque.encode_xdr!()

    {:ok, variable_opaque}
  end

  @doc """
  Encode a `XDR.String` structure into a XDR format.
  If the `string` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(string) do
    case encode_xdr(string) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(StringError, reason)
    end
  end

  @doc """
  Decode the String in XDR format to a `XDR.String` structure.
  """
  @impl true
  def decode_xdr(bytes, string \\ %{max_length: 4_294_967_295})
  def decode_xdr(bytes, _string) when not is_binary(bytes), do: {:error, :not_binary}

  def decode_xdr(bytes, %{max_length: max_length}) do
    variable_struct = VariableOpaque.new(nil, max_length)

    {binary, rest} = VariableOpaque.decode_xdr!(bytes, variable_struct)

    decoded_string =
      binary
      |> Map.get(:opaque)
      |> String.graphemes()
      |> Enum.join("")
      |> new(max_length)

    {:ok, {decoded_string, rest}}
  end

  @doc """
  Decode the String in XDR format to a `XDR.String` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, string \\ %{max_length: 4_294_967_295})

  def decode_xdr!(bytes, string) do
    case decode_xdr(bytes, string) do
      {:ok, result} -> result
      {:error, reason} -> raise(StringError, reason)
    end
  end
end

defmodule FixedOpaque  do
  @behaviour XDR.Declaration

  defstruct [:opaque, :length]

  alias XDR.FixedOpaqueError

  @type opaque :: binary() | nil

  @typedoc """
  `XDR.FixedOpaque` structure type specification.
  """
  @type t :: %XDR.FixedOpaque{opaque: opaque(), length: integer}

  @doc """
  Create a new `XDR.FixedOpaque` structure with the `opaque` and `length` passed.
  """
  @spec new(opaque :: opaque(), length :: integer()) :: t()
  def new(opaque, length), do: %XDR.FixedOpaque{opaque: opaque, length: length}

  @doc """
  Encode a `XDR.FixedOpaque` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%{opaque: opaque}) when not is_binary(opaque), do: {:error, :not_binary}
  def encode_xdr(%{length: length}) when not is_integer(length), do: {:error, :not_number}

  def encode_xdr(%{opaque: opaque, length: length}) when length != byte_size(opaque),
    do: {:error, :invalid_length}

  def encode_xdr(%{opaque: opaque, length: length}) when rem(length, 4) === 0, do: {:ok, opaque}

  def encode_xdr(%{opaque: opaque, length: length}) when rem(length, 4) != 0 do
    (opaque <> <<0>>) |> new(length + 1) |> encode_xdr()
  end

  @doc """
  Encode a `XDR.FixedOpaque` structure into a XDR format.
  If the `opaque` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(opaque) do
    case encode_xdr(opaque) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(FixedOpaqueError, reason)
    end
  end

  @doc """
  Decode the Fixed-Length Opaque Data in XDR format to a `XDR.FixedOpaque` structure.
  """
  @impl true
  def decode_xdr(bytes, _opaque) when not is_binary(bytes), do: {:error, :not_binary}

  def decode_xdr(bytes, _opaque) when rem(byte_size(bytes), 4) != 0,
    do: {:error, :not_valid_binary}

  def decode_xdr(_bytes, %{length: length}) when not is_integer(length), do: {:error, :not_number}

  def decode_xdr(bytes, %{length: length}) when length > byte_size(bytes),
    do: {:error, :exceed_length}

  def decode_xdr(bytes, %{length: length}) do
    required_padding = get_required_padding(length)

    <<fixed_opaque::bytes-size(length), _padding::bytes-size(required_padding), rest::binary>> =
      bytes

    decoded_opaque = new(fixed_opaque, length)
    {:ok, {decoded_opaque, rest}}
  end

  @doc """
  Decode the Fixed-Length Array in XDR format to a `XDR.FixedOpaque` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, opaque) do
    case decode_xdr(bytes, opaque) do
      {:ok, result} -> result
      {:error, reason} -> raise(FixedOpaqueError, reason)
    end
  end

  @spec get_required_padding(length :: integer()) :: integer()
  defp get_required_padding(length) when rem(length, 4) == 0, do: 0
  defp get_required_padding(length), do: 4 - rem(length, 4)
end

defmodule VariableOpaque do
  @behaviour XDR.Declaration

  alias XDR.{FixedOpaque, UInt, VariableOpaqueError}

  defstruct [:opaque, :max_size]

  @type opaque :: binary() | nil

  @typedoc """
  `XDR.VariableOpaque` structure type specification.
  """
  @type t :: %XDR.VariableOpaque{opaque: opaque(), max_size: integer()}

  @doc """
  Create a new `XDR.VariableOpaque` structure with the `opaque` and `max_size` passed.
  """
  @spec new(opaque :: opaque(), max_size :: integer()) :: t()
  def new(opaque, max_size \\ 4_294_967_295)
  def new(opaque, max_size), do: %XDR.VariableOpaque{opaque: opaque, max_size: max_size}

  @doc """
  Encode a `XDR.VariableOpaque` structure into a XDR format.
  """
  @impl true
  def encode_xdr(%{opaque: opaque}) when not is_binary(opaque),
    do: {:error, :not_binary}

  def encode_xdr(%{max_size: max_size}) when not is_integer(max_size),
    do: {:error, :not_number}

  def encode_xdr(%{max_size: max_size}) when max_size <= 0,
    do: {:error, :exceed_lower_bound}

  def encode_xdr(%{max_size: max_size}) when max_size > 4_294_967_295,
    do: {:error, :exceed_upper_bound}

  def encode_xdr(%{opaque: opaque, max_size: max_size})
      when byte_size(opaque) > max_size,
      do: {:error, :invalid_length}

  def encode_xdr(%{opaque: opaque}) do
    length = byte_size(opaque)
    opaque_length = length |> UInt.new() |> UInt.encode_xdr!()
    fixed_opaque = FixedOpaque.new(opaque, length) |> FixedOpaque.encode_xdr!()
    {:ok, opaque_length <> fixed_opaque}
  end

  @doc """
  Encode a `XDR.VariableOpaque` structure into a XDR format.
  If the `opaque` is not valid, an exception is raised.
  """
  @impl true
  def encode_xdr!(opaque) do
    case encode_xdr(opaque) do
      {:ok, binary} -> binary
      {:error, reason} -> raise(VariableOpaqueError, reason)
    end
  end

  @doc """
  Decode the Variable-Length Opaque Data in XDR format to a `XDR.VariableOpaque` structure.
  """
  @impl true
  def decode_xdr(bytes, opaque \\ %{max_size: 4_294_967_295})

  def decode_xdr(bytes, _opaque) when not is_binary(bytes),
    do: {:error, :not_binary}

  def decode_xdr(_bytes, %{max_size: max_size}) when not is_integer(max_size),
    do: {:error, :not_number}

  def decode_xdr(_bytes, %{max_size: max_size}) when max_size <= 0,
    do: {:error, :exceed_lower_bound}

  def decode_xdr(_bytes, %{max_size: max_size}) when max_size > 4_294_967_295,
    do: {:error, :exceed_upper_bound}

  def decode_xdr(bytes, %{max_size: max_size}) do
    {uint, rest} = UInt.decode_xdr!(bytes)
    uint.datum |> get_decoded_value(rest, max_size)
  end

  @doc """
  Decode the Variable-Length Opaque Data in XDR format to a `XDR.VariableOpaque` structure.
  If the binaries are not valid, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, opaque \\ %{max_size: 4_294_967_295})

  def decode_xdr!(bytes, opaque) do
    case decode_xdr(bytes, opaque) do
      {:ok, result} -> result
      {:error, reason} -> raise(VariableOpaqueError, reason)
    end
  end

  @spec get_decoded_value(length :: integer(), rest :: binary(), max :: integer()) ::
          {:ok, {t(), binary()}}
  defp get_decoded_value(length, _rest, max) when length > max, do: {:error, :length_over_max}

  defp get_decoded_value(length, rest, _max) when length > byte_size(rest),
    do: {:error, :length_over_rest}

  defp get_decoded_value(length, rest, max) do
    {fixed_opaque, rest} = FixedOpaque.decode_xdr!(rest, %XDR.FixedOpaque{length: length})
    decoded_variable_array = fixed_opaque.opaque |> new(max)
    {:ok, {decoded_variable_array, rest}}
  end
end

defmodule void do
  @behaviour XDR.Declaration

  @type t :: %__MODULE__{value: nil}

  defstruct [:value]

  @spec new(value :: nil) :: t()
  def new(_val \\ nil), do: %__MODULE__{value: nil}

  @impl true
  def encode_xdr(%__MODULE__{}) do
    XDR.Void.encode_xdr(%XDR.Void{})
  end

  @impl true
  def encode_xdr!(%__MODULE__{}) do
    XDR.Void.encode_xdr!(%XDR.Void{})
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.Void.decode_xdr(bytes) do
      {:ok, {nil, rest}} -> {:ok, {new(), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {nil, rest} = XDR.Void.decode_xdr!(bytes)
    {new(), rest}
  end
end

  @doc """
  Decode the XDR format to a void format.
  """
  @impl true
  def decode_xdr(bytes, _void \\ nil)
  def decode_xdr(<<rest::binary>>, _), do: {:ok, {nil, rest}}
  def decode_xdr(_, _), do: {:error, :not_binary}

  @doc """
  Decode the XDR format to a void format.
  If the binary is not a valid void, an exception is raised.
  """
  @impl true
  def decode_xdr!(bytes, _void \\ nil) do
    case decode_xdr(bytes) do
      {:ok, result} -> result
      {:error, reason} -> raise(VoidError, reason)
    end
  end
end
