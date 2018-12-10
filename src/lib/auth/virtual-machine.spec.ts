// tslint:disable:no-expression-statement no-magic-numbers readonly-array
import test from 'ava';

import { MinimumProgramState, StackMachineState } from './state';
import {
  createAuthenticationVirtualMachine,
  InstructionSet
} from './virtual-machine';

enum simpleOps {
  OP_0 = 0,
  OP_INCREMENT = 1,
  OP_DECREMENT = 2,
  OP_ADD = 3,
  OP_CODESEPARATOR = 171
}

enum SimpleError {
  UNDEFINED = 'The program called an undefined opcode.',
  EMPTY_STACK = 'The program tried to pop from an empty stack.'
}

interface SimpleEvaluationState
  extends MinimumProgramState,
    StackMachineState<number> {
  // tslint:disable-next-line:readonly-keyword
  error?: SimpleError;
}

const simpleInstructionSet: InstructionSet<SimpleEvaluationState> = {
  before: (state: SimpleEvaluationState) => {
    // tslint:disable-next-line:no-object-mutation no-expression-statement
    state.ip++;
    return state;
  },
  clone: (state: SimpleEvaluationState) => ({
    ...(state.error !== undefined ? { error: state.error } : {}),
    ip: state.ip,
    script: state.script.slice(),
    stack: state.stack.slice()
  }),
  continue: (state: SimpleEvaluationState) =>
    state.error === undefined && state.ip < state.script.length,
  undefined: {
    asm: 'undefined',
    description: 'Error: the program called an undefined opcode.',
    operation: (state: SimpleEvaluationState) => {
      // tslint:disable-next-line:no-object-mutation
      state.error = SimpleError.UNDEFINED;
      return state;
    }
  },
  [simpleOps.OP_0]: {
    asm: 'OP_0',
    description: 'Push a 0 onto the stack.',
    operation: (state: SimpleEvaluationState) => {
      state.stack.push(0);
      return state;
    }
  },
  [simpleOps.OP_INCREMENT]: {
    asm: 'OP_INCREMENT',
    description: 'Add 1 to the top stack item.',
    operation: (state: SimpleEvaluationState) => {
      const top = state.stack.pop();
      top === undefined
        ? // tslint:disable-next-line:no-object-mutation
          (state.error = SimpleError.EMPTY_STACK)
        : state.stack.push(top + 1);
      return state;
    }
  },
  [simpleOps.OP_DECREMENT]: {
    asm: 'OP_DECREMENT',
    description: 'Subtract 1 from the top stack item.',
    operation: (state: SimpleEvaluationState) => {
      const top = state.stack.pop();
      top === undefined
        ? // tslint:disable-next-line:no-object-mutation
          (state.error = SimpleError.EMPTY_STACK)
        : state.stack.push(top - 1);
      return state;
    }
  },
  [simpleOps.OP_ADD]: {
    asm: 'OP_ADD',
    description: (state: SimpleEvaluationState) =>
      `Pop the top two items off the stack (${state.stack.pop()}, ${state.stack.pop()}) and push their sum onto the stack.`,
    operation: (state: SimpleEvaluationState) => {
      const a = state.stack.pop();
      const b = state.stack.pop();
      a === undefined || b === undefined
        ? // tslint:disable-next-line:no-object-mutation
          (state.error = SimpleError.EMPTY_STACK)
        : state.stack.push(a + b);
      return state;
    }
  },
  [simpleOps.OP_CODESEPARATOR]: {
    asm: (state: SimpleEvaluationState) => `OP_CODESEPARATOR(ip: ${state.ip})`,
    description:
      'Used internally to separate the unlocking and locking scripts.',
    operation: (state: SimpleEvaluationState) => state
  }
};
// tslint:enable: no-object-mutation

const vm = createAuthenticationVirtualMachine(simpleInstructionSet);

const serializeScript = (
  unlockingScript: Uint8Array,
  lockingScript: Uint8Array
) => {
  const serialized = new Uint8Array(
    unlockingScript.length + lockingScript.length + 1
  );
  serialized.set(unlockingScript, 0);
  serialized.set([simpleOps.OP_CODESEPARATOR], unlockingScript.length);
  serialized.set(lockingScript, unlockingScript.length + 1);
  return serialized;
};

test('vm.debug with a simple instruction set', t => {
  const unlockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_INCREMENT,
    simpleOps.OP_INCREMENT
  ]);

  const lockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_DECREMENT,
    simpleOps.OP_ADD
  ]);

  const script = serializeScript(unlockingScript, lockingScript);

  const program = {
    ip: 0,
    script,
    stack: []
  };

  t.deepEqual(vm.debug(program), [
    {
      asm: '',
      description: 'Begin script evaluation.',
      state: {
        ip: 0,
        script,
        stack: []
      }
    },
    {
      asm: 'OP_0',
      description: 'Push a 0 onto the stack.',
      state: {
        ip: 1,
        script,
        stack: [0]
      }
    },
    {
      asm: 'OP_INCREMENT',
      description: 'Add 1 to the top stack item.',
      state: {
        ip: 2,
        script,
        stack: [1]
      }
    },
    {
      asm: 'OP_INCREMENT',
      description: 'Add 1 to the top stack item.',
      state: {
        ip: 3,
        script,
        stack: [2]
      }
    },
    {
      asm: 'OP_CODESEPARATOR(ip: 4)',
      description:
        'Used internally to separate the unlocking and locking scripts.',
      state: {
        ip: 4,
        script,
        stack: [2]
      }
    },
    {
      asm: 'OP_0',
      description: 'Push a 0 onto the stack.',
      state: {
        ip: 5,
        script,
        stack: [2, 0]
      }
    },
    {
      asm: 'OP_DECREMENT',
      description: 'Subtract 1 from the top stack item.',
      state: {
        ip: 6,
        script,
        stack: [2, -1]
      }
    },
    {
      asm: 'OP_ADD',
      description:
        'Pop the top two items off the stack (-1, 2) and push their sum onto the stack.',
      state: {
        ip: 7,
        script,
        stack: [1]
      }
    }
  ]);

  t.deepEqual(vm.evaluate(program), {
    ip: 7,
    script,
    stack: [1]
  });
});

test('vm.evaluate does not mutate the original state', t => {
  const unlockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_INCREMENT,
    simpleOps.OP_INCREMENT
  ]);

  const lockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_DECREMENT,
    simpleOps.OP_ADD
  ]);

  const script = serializeScript(unlockingScript, lockingScript);

  const programUnchanged = {
    ip: 0,
    script,
    stack: []
  };

  t.deepEqual(vm.evaluate(programUnchanged), {
    ip: 7,
    script,
    stack: [1]
  });

  t.deepEqual(programUnchanged, {
    ip: 0,
    script,
    stack: []
  });
});

test('vm.step does not mutate the original state', t => {
  const unlockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_INCREMENT,
    simpleOps.OP_INCREMENT
  ]);

  const lockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_DECREMENT,
    simpleOps.OP_ADD
  ]);

  const script = serializeScript(unlockingScript, lockingScript);

  const programUnchanged = {
    ip: 6,
    script,
    stack: [2, -1]
  };

  t.deepEqual(vm.step(programUnchanged), {
    ip: 7,
    script,
    stack: [1]
  });

  t.deepEqual(programUnchanged, {
    ip: 6,
    script,
    stack: [2, -1]
  });
});

test('vm.stepMutate does not clone (mutating the original state)', t => {
  const unlockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_INCREMENT,
    simpleOps.OP_INCREMENT
  ]);

  const lockingScript = new Uint8Array([
    simpleOps.OP_0,
    simpleOps.OP_DECREMENT,
    simpleOps.OP_ADD
  ]);

  const script = serializeScript(unlockingScript, lockingScript);

  const programChanged: SimpleEvaluationState = {
    ip: 6,
    script,
    stack: [2, -1]
  };

  t.deepEqual(vm.stepMutate(programChanged), {
    ip: 7,
    script,
    stack: [1]
  });

  t.deepEqual(programChanged, {
    ip: 7,
    script,
    stack: [1]
  });
});
