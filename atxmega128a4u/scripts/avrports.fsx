#r "r2pipe.dll"
#r "packages/FSharp.Data/lib/net40/FSharp.Data.dll"

open System
open System.Globalization
open System.IO
open r2pipe
open FSharp.Data
open FSharp.Data.JsonExtensions

type OpType = OP_IO | OP_RAM | OP_JMP | OP_OTHER

let readOpCodes (r2p:RlangPipe, bytes:int)  = 
  seq {
    let cmd = String.Format("pDj {0}", bytes)
    let flow = JsonValue.Parse (r2p.RunCommand cmd)
    for record in flow do
      yield record
  }

let loadDefs (filename:string) =
    let arrayPorts : string array = Array.zeroCreate 255     

    let stream = new StreamReader(filename)

    let readLn () = 
      let line = stream.ReadLine()
      match line with
        | null -> stream.Close(); ["EOF"]
        | _ -> line.Split([|' '; '\t'|]) |> Array.toList

    let rec parseDef x =
      match x with
          ("EOF"::_, state) -> arrayPorts        
        | (_::"*****"::"I/O"::_, state) -> parseDef (readLn(), 1)
        | (_::"*****"::"INTERRUPT"::_, state) -> parseDef (readLn(), 2)
        | (_::"*****"::_, state) -> parseDef (readLn(), 0)
        | (".equ"::var::"="::addr::t, 1) ->           
            Array.set arrayPorts (Int32.Parse(addr.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber)) var;
            parseDef (readLn(), 1)
        | (t, state) -> parseDef (readLn(), state)


    parseDef (readLn(), 0)

[<EntryPoint>]
let main argv =
    let r2p = new RlangPipe()

    let info = JsonValue.Parse (r2p.RunCommand "ij")
    let instr = (JsonValue.Parse (r2p.RunCommand "pdj 1")).[0]

    let arrayPorts = loadDefs argv.[0]

    let convertPort (str:string, opType:OpType):string =
      let port = Int32.Parse(str.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber)

      if opType = OP_IO then
        arrayPorts.[port]
      else if opType = OP_RAM then
        if port > 0xFF then
          null
        else if port < 0x60 then
          arrayPorts.[port - 0x20] 
        else
          arrayPorts.[port]
      else
        null


    let bytes = 
      if argv.Length = 3 then
        Int32.Parse(argv.[2].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber) 
        - Int32.Parse(argv.[1].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber)
      else
        info?core?size.AsInteger() - instr?offset.AsInteger()

    let opcodes = readOpCodes (r2p, bytes)

    let tmp = opcodes 
              |> Seq.map ( fun (a) ->          
                a?offset.AsInteger(), 
                a?opcode.AsString().Split([|' '; ','|], StringSplitOptions.RemoveEmptyEntries), 
                a?size.AsInteger()       
                ) 
              |> Seq.filter (fun (offset, opcode, size) ->     opcode.[0] = "in" 
                                                            || opcode.[0] = "out" 
                                                            || opcode.[0] = "lds" 
                                                            || opcode.[0] = "sts" 
                                                            || opcode.[0] = "sbi" 
                                                            || opcode.[0] = "cbi"
                            )
              |> Seq.map (fun (offset, opcode, size) ->
                let hexed_offset = "0x" + offset.ToString("X")
                let lst = opcode |> Array.toList  
                match lst with
                    "in"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op2, OP_IO), hexed_offset ))
                  | "out"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op1, OP_IO), hexed_offset ))
                  | "cbi"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op1, OP_IO), hexed_offset ))
                  | "sbi"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op1, OP_IO), hexed_offset ))
                  | "sts"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op1, OP_RAM), hexed_offset ))
                  | "lds"::op1::op2::t -> r2p.RunCommand (String.Format( "CC {0} @ {1}", convertPort (op2, OP_RAM), hexed_offset ))
                  | _ -> ""
                ) 
              |> Seq.length

    0 
