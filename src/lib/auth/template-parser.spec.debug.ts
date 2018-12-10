const testExpression = `
// this is a comment

/*
This is
a multi-line
comment
*/

<$(OP_1 OP_HASH160)>

$(
  // begin a new empty stack in the stack debugger
  OP_1
  OP_2
  OP_ADD
) // should result in an OP_PUSHBYTES_3

0x010203 // should be pushed

validIdentifier
valid_identifier

<1>
<0x01>

<"abc">
<'abc'>

OP_1 OP_2 OP_3
`;
