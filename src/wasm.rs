use crate::errors::SideFuzzError;
use float_duration::{FloatDuration, TimePoint};
use std::fs::File;
use std::io::prelude::*;
use std::time::Instant;

use wasmi::*;

pub struct WasmModule {
    module: Vec<u8>,
    store: Store<()>,
    instance: Instance,
    memory: Memory,
    fuzz_ptr: usize,
    fuzz_len: u32,
    input_is_str: bool,
}

impl WasmModule {
    pub fn new(module: Vec<u8>) -> Result<Self, SideFuzzError> {
	let engine = Engine::new(&Config::default().consume_fuel(true));

        let parsed = Module::new(&engine, module.as_slice())?;
	let mut store = Store::new(parsed.engine(), ());
        let instance = Linker::<()>::new().instantiate(&mut store, &parsed)?.ensure_no_start(&mut store)?;

        // Get memory instance exported by name 'mem' from the module instance.
        let memory = instance.get_export(&store, "memory");
        let memory = memory.ok_or(SideFuzzError::WasmModuleNoMemory)?;
        let memory = memory
            .into_memory()
            .ok_or(SideFuzzError::WasmModuleBadMemory)?;

        let mut wasm_module = Self {
            module: module,
	    store: store,
            instance: instance,
            memory: memory,
            fuzz_ptr: 0,
            fuzz_len: 0,
            input_is_str: false,
        };

        // Set input pointers
        wasm_module.set_input_pointer()?;

        // Prime lazy statics
        wasm_module.prime_lazy_statics()?;

        Ok(wasm_module)
    }

    pub fn from_file(filename: &str) -> Result<Self, SideFuzzError> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Self::new(buf)?)
    }

    pub fn fuzz_len(&self) -> usize {
        self.fuzz_len as usize
    }

    pub fn input_is_str(&self) -> bool {
        self.input_is_str
    }


    pub fn bytes(&self) -> Vec<u8> {
        self.module.clone()
    }

    // Count instructions for a given input
    pub fn count_instructions(&mut self, input: &[u8]) -> Result<u64, SideFuzzError> {
        self.memory
            .write(&mut self.store, self.fuzz_ptr, input)
            .map_err(|e| SideFuzzError::MemorySetError(e.into()))?;
        self.store.add_fuel(u64::MAX - self.store.fuel_consumed().unwrap()).unwrap();
        let result = self.instance.get_export(&self.store, "fuzz").ok_or(SideFuzzError::WasmModuleNoInputPointer)?.into_func().ok_or(SideFuzzError::WasmModuleNoInputPointer)?.call(&mut self.store, &[], &mut []);
        if let Err(err) = result {
            // If we've got a MemoryAccessOutOfBounds error, then we've corrupted our memory.
            // In a real application this would be a crash, so reboot the instance and start over.
            if let wasmi::Error::Trap(trap) = &err {
                if let Some(wasmi::core::TrapCode::MemoryOutOfBounds) = trap.trap_code() {
                    self.reboot();
                }
            }
            return Err(SideFuzzError::WasmError(err));
        }
        let count = u64::MAX - self.store.fuel_consumed().unwrap();

        Ok(count)
    }

    // Restart / Reboot the instance
    fn reboot(&mut self) {
        // This should be ok to expect here since the module has already been instantiated previously.
        let new = Self::new(self.module.clone()).expect("Could not reboot wasm module instance.");
	self.store = new.store;
	self.instance = new.instance;
	self.memory = new.memory;
    }

    // Measure and report the running time for a single execution
    pub fn measure_time(&mut self) -> Result<FloatDuration, SideFuzzError> {
        let input: Vec<u8> = (0..self.fuzz_len).map(|_| rand::random::<u8>()).collect();
        let start_time = Instant::now();
        self.count_instructions(&input)?;
        let end_time = Instant::now();

        Ok(end_time.float_duration_since(start_time).unwrap())
    }

    // Prime lazy statics
    pub fn prime_lazy_statics(&mut self) -> Result<(), SideFuzzError> {
        // Prime until it completes successfully (limited to 100 attemps).
        let mut i = 0;
        loop {
            let input: Vec<u8> = (0..self.fuzz_len).map(|_| rand::random::<u8>()).collect();
            let result = self.count_instructions(&input);
            if result.is_ok() {
                return Ok(());
            }
            i += 1;
            if i >= 100 {
                return Err(result.unwrap_err());
            }
        }
    }

    // Set the input fuzz length
    fn set_input_pointer(&mut self) -> Result<(), SideFuzzError> {
        // Call "sidefuzz" to prime INPUT static global and set it's length
        let _ = crate::black_box(self.count_instructions(&vec![]));

        // Call the "input_pointer" exported function to get the pointer to the input
        let mut input_pointer = vec![wasmi::Value::I32(0); 1];
        self
            .instance
            .get_export(&self.store, "input_pointer").ok_or(SideFuzzError::WasmModuleNoInputPointer)?.into_func().ok_or(SideFuzzError::WasmModuleNoInputPointer)?.call(&mut self.store, &[], &mut input_pointer)?;

        // Call the "input_len" exported function to get the input length
        let mut input_len = vec![wasmi::Value::I64(0); 1];
        dbg!(self
            .instance
            .get_export(&self.store, "input_len").ok_or(SideFuzzError::WasmModuleBadInpuLen)?.into_func().ok_or(SideFuzzError::WasmModuleBadInpuLen)?.call(&mut self.store, &[], &mut input_len))?;
        dbg!(input_len.clone());

        // Call the "input_is_str" exported function to check if input is a string
        dbg!(0);
        let mut input_is_str = vec![wasmi::Value::I32(0); 1];
        dbg!(self.instance.exports(&self.store));
        dbg!(self
            .instance
            .get_export(&self.store, "input_is_str")).ok_or(SideFuzzError::WasmModuleBadInpuLen)?.into_func().ok_or(SideFuzzError::WasmModuleBadInpuLen)?.call(&mut self.store, &[], &mut input_is_str)?;
        dbg!(1);

        let input_pointer = match input_pointer[0] {
            wasmi::Value::I32(inner) => inner,
            _ => {
                return Err(SideFuzzError::WasmModuleBadInputPointer);
            }
        };
        dbg!(2);

        let input_len = match dbg!(input_len[0].clone()) {
            wasmi::Value::I32(inner) => inner,
            _ => {
                return Err(SideFuzzError::WasmModuleBadInpuLen);
            }
        };
        if input_len > 1024 {
            return Err(SideFuzzError::FuzzLenTooLong(input_len as u32));
        }

let input_is_str = match input_is_str[0] {
wasmi::Value::I32(inner) => inner > 0,
_ => {
return Err(SideFuzzError::WasmModuleBadInpuLen);
}
};

self.fuzz_ptr = input_pointer as usize;
self.fuzz_len = input_len as u32;
self.input_is_str = input_is_str;

        Ok(())
    }
}

impl Clone for WasmModule {
    fn clone(&self) -> Self {
        // This should be ok to expect here since the module has already been instantiated previously.
        Self::new(self.module.clone()).expect("Unable to clone wasm module")
    }
}
