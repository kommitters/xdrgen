defmodule MyXDR.Arr do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `Arr` type.
  """

  @behaviour XDR.Declaration

  @type t :: %__MODULE__{datum: integer()}

  defstruct [:datum]

  @spec new(value :: integer()) :: t()
  def new(value), do: %__MODULE__{datum: value}

  @impl true
  def encode_xdr(%__MODULE__{datum: value}) do
    XDR.Int.encode_xdr(%XDR.Int{datum: value})
  end

  @impl true
  def encode_xdr!(%__MODULE__{datum: value}) do
    XDR.Int.encode_xdr!(%XDR.Int{datum: value})
  end

  @impl true
  def decode_xdr(bytes, term \\ nil)

  def decode_xdr(bytes, _term) do
    case XDR.Int.decode_xdr(bytes) do
      {:ok, {%XDR.Int{datum: value}, rest}} -> {:ok, {new(value), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, term \\ nil)

  def decode_xdr!(bytes, _term) do
    {%XDR.Int{datum: value}, rest} = XDR.Int.decode_xdr!(bytes)
    {new(value), rest}
  end
end
