defmodule MyXDR.MyUnionTwo do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `MyUnionTwo` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.{
    Int,
    Foo
  }

  @struct_spec XDR.Struct.new(
    some_int: Int,
    foo: Foo
  )

  @type some_int :: Int.t()
  @type foo :: Foo.t()

  @type t :: %__MODULE__{some_int: some_int(), foo: foo()}

  defstruct [:some_int, :foo]

  @spec new(some_int :: some_int(), foo :: foo()) :: t()
  def new(
    %Int{} = some_int,
    %Foo{} = foo
  ),
  do: %__MODULE__{some_int: some_int, foo: foo}

  @impl true
  def encode_xdr(%__MODULE__{some_int: some_int, foo: foo}) do
    [some_int: some_int, foo: foo]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{some_int: some_int, foo: foo}) do
    [some_int: some_int, foo: foo]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, struct \\ @struct_spec)

  def decode_xdr(bytes, struct) do
    case XDR.Struct.decode_xdr(bytes, struct) do
      {:ok, {%XDR.Struct{components: [some_int: some_int, foo: foo]}, rest}} ->
        {:ok, {new(some_int, foo), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, struct \\ @struct_spec)

  def decode_xdr!(bytes, struct) do
    {%XDR.Struct{components: [some_int: some_int, foo: foo]}, rest} =
      XDR.Struct.decode_xdr!(bytes, struct)
    {new(some_int, foo), rest}
  end
end
