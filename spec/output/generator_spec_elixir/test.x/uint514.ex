defmodule MyXDR.Uint514 do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `Uint514` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.VariableOpaque64

  @type t :: %__MODULE__{value: binary()}

  defstruct [:value]

  @spec new(value :: binary()) :: t()
  def new(value), do: %__MODULE__{value: value}

  @impl true
  def encode_xdr(%__MODULE__{value: value}) do
    value
    |> VariableOpaque64.new()
    |> VariableOpaque64.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{opaque: opaque}) do
    value
    |> VariableOpaque64.new()
    |> VariableOpaque64.encode_xdr()
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.VariableOpaque64.decode_xdr(bytes, term) do
      {:ok, {%XDR.VariableOpaque64{opaque: value}, rest}} -> {:ok, {new(value), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.VariableOpaque64{opaque: value}, rest} = XDR.VariableOpaque64.decode_xdr!(bytes)
    {new(value), rest}
  end
end
