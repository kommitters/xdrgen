defmodule MyXDR.MyStructList do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `MyStructList` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.MyStruct

  @array_type MyStruct

  @array_spec %{type: @array_type}

  @type t :: %__MODULE__{my_structs: list(MyStruct.t())}

  defstruct [:my_structs]

  @spec new(my_structs :: list(MyStruct.t())) :: t()
  def new(my_structs), do: %__MODULE__{my_structs: my_structs}

  @impl true
  def encode_xdr(%__MODULE__{my_structs: my_structs}) do
    my_structs
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{my_structs: my_structs}) do
    my_structs
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, spec \\ @array_spec)

  def decode_xdr(bytes, spec) do
    case XDR.VariableArray.decode_xdr(bytes, spec) do
      {:ok, {my_structs, rest}} -> {:ok, {new(my_structs), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, spec \\ @array_spec)

  def decode_xdr!(bytes, spec) do
    {my_structs, rest} = XDR.VariableArray.decode_xdr!(bytes, spec)
    {new(my_structs), rest}
  end
end
