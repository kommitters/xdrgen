defmodule MyXDR.MyStruct do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `MyStruct` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.{ 
    Uint512,
    OptHash1,
    Int1,
    UInt,
    Float,
    DoubleFloat,
    Bool
  } 

  @struct_spec XDR.Struct.new(
    field1: Uint512,
    field2: OptHash1,
    field3: Int1,
    field4: UInt,
    field5: Float,
    field6: DoubleFloat,
    field7: Bool
  )

  @type field1 :: Uint512.t()
  @type field2 :: OptHash1.t()
  @type field3 :: Int1.t()
  @type field4 :: UInt.t()
  @type field5 :: Float.t()
  @type field6 :: DoubleFloat.t()
  @type field7 :: Bool.t()

  @type t :: %__MODULE__{field1: field1(), field2: field2(), field3: field3(), field4: field4(), field5: field5(), field6: field6(), field7: field7()}

  defstruct [:field1, :field2, :field3, :field4, :field5, :field6, :field7]

  @spec new(field1 :: field1(), field2 :: field2(), field3 :: field3(), field4 :: field4(), field5 :: field5(), field6 :: field6(), field7 :: field7()) :: t()
  def new(
    %Uint512{} = field1,
    %OptHash1{} = field2,
    %Int1{} = field3,
    %UInt{} = field4,
    %Float{} = field5,
    %DoubleFloat{} = field6,
    %Bool{} = field7
  ),
  do: %__MODULE__{field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7}

  @impl true
  def encode_xdr(%__MODULE__{field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7}) do
    [field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7}) do
    [field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, struct \\ @struct_spec)

  def decode_xdr(bytes, struct) do
    case XDR.Struct.decode_xdr(bytes, struct) do
      {:ok, {%XDR.Struct{components: [field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7]}, rest}} ->
        {:ok, {new(field1, field2, field3, field4, field5, field6, field7), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, struct \\ @struct_spec)

  def decode_xdr!(bytes, struct) do
    {%XDR.Struct{components: [field1: field1, field2: field2, field3: field3, field4: field4, field5: field5, field6: field6, field7: field7]}, rest} =
      XDR.Struct.decode_xdr!(bytes, struct)
    {new(field1, field2, field3, field4, field5, field6, field7), rest}
  end
end
