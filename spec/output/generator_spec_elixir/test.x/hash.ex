defmodule MyXDR.Hash do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `Hash` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.Opaque64

  @type t :: %__MODULE__{value: binary()}

  defstruct [:value]

  @spec new(value :: binary()) :: t()
  def new(value), do: %__MODULE__{value: value}

  @impl true
  def encode_xdr(%__MODULE__{value: value}) do
    value
    |> Opaque64.new()
    |> Opaque64.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{opaque: opaque}) do
    value
    |> Opaque64.new()
    |> Opaque64.encode_xdr()
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.Opaque64.decode_xdr(bytes, term) do
      {:ok, {%XDR.Opaque64{opaque: value}, rest}} -> {:ok, {new(value), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.Opaque64{opaque: value}, rest} = XDR.Opaque64.decode_xdr!(bytes)
    {new(value), rest}
  end
end
