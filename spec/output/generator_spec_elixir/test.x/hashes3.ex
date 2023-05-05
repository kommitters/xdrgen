defmodule MyXDR.Hashes3 do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `Hashes3` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.Hash

  @array_type Hash

  @array_spec %{type: @array_type}

  @type t :: %__MODULE__{items: list(Hash.t())}

  defstruct [:items]

  @spec new(items :: list(Hash.t())) :: t()
  def new(items), do: %__MODULE__{items: items}

  @impl true
  def encode_xdr(%__MODULE__{items: items}) do
    items
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{items: items}) do
    items
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, spec \\ @array_spec)

  def decode_xdr(bytes, spec) do
    case XDR.VariableArray.decode_xdr(bytes, spec) do
      {:ok, {items, rest}} -> {:ok, {new(items), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, spec \\ @array_spec)

  def decode_xdr!(bytes, spec) do
    {items, rest} = XDR.{list_type}.decode_xdr!(bytes, spec)
    {new(items), rest}
  end
end
