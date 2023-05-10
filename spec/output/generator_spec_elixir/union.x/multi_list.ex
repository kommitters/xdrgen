defmodule MyXDR.MultiList do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `MultiList` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.Multi

  @array_type Multi

  @array_spec %{type: @array_type}

  @type t :: %__MODULE__{multis: list(Multi.t())}

  defstruct [:multis]

  @spec new(multis :: list(Multi.t())) :: t()
  def new(multis), do: %__MODULE__{multis: multis}

  @impl true
  def encode_xdr(%__MODULE__{multis: multis}) do
    multis
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{multis: multis}) do
    multis
    |> XDR.VariableArray.new(@array_type)
    |> XDR.VariableArray.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, spec \\ @array_spec)

  def decode_xdr(bytes, spec) do
    case XDR.VariableArray.decode_xdr(bytes, spec) do
      {:ok, {multis, rest}} -> {:ok, {new(multis), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, spec \\ @array_spec)

  def decode_xdr!(bytes, spec) do
    {multis, rest} = XDR.VariableArray.decode_xdr!(bytes, spec)
    {new(multis), rest}
  end
end
