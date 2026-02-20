// FindPYMEthods.java
// =============================================================================
// Ghidra Script: memory scan for PyMethodDef tables (Python 2.7, 32-bit)
// =============================================================================
//
// PyMethodDef structure (CPython 2.7, 32-bit):
//
//   struct PyMethodDef {
//       const char *ml_name;   // +0x00  ptr -> ASCII string (identifier)
//       PyCFunction ml_meth;   // +0x04  ptr -> executable function
//       int         ml_flags;  // +0x08  combination of METH_* flags
//       const char *ml_doc;    // +0x0C  ptr -> ASCII string or NULL
//   };  // sizeof = 16 bytes (0x10)
//
// @category   Python.Analysis
// @author     Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class FindPYMEthods extends GhidraScript {

    // -----------------------------------------------------------------------
    // Python 2.7 METH_* flag constants
    // -----------------------------------------------------------------------
    static final int METH_VARARGS  = 0x0001;
    static final int METH_KEYWORDS = 0x0002;
    static final int METH_NOARGS   = 0x0004;
    static final int METH_O        = 0x0008;
    static final int METH_CLASS    = 0x0010;
    static final int METH_STATIC   = 0x0020;
    static final int METH_COEXIST  = 0x0040;

    static final int ALL_VALID_FLAGS = METH_VARARGS | METH_KEYWORDS | METH_NOARGS
            | METH_O | METH_CLASS | METH_STATIC | METH_COEXIST;

    // Valid calling-convention combinations (bits 0-3)
    static final Set<Integer> VALID_CC = new HashSet<>(
            Arrays.asList(0, METH_VARARGS, METH_VARARGS | METH_KEYWORDS, METH_NOARGS, METH_O));

    static final int ENTRY_SIZE        = 16;
    static final int MIN_TABLE_ENTRIES = 2;
    static final int MAX_NAME_LEN     = 256;
    static final int MAX_DOC_LEN      = 4096;

    // -----------------------------------------------------------------------
    // Instance fields
    // -----------------------------------------------------------------------
    private Memory memory;
    private AddressSpace defaultSpace;
    private List<long[]> exeRanges;    // executable ranges [start, end]
    private List<long[]> initRanges;   // initialized ranges [start, end]

    // -----------------------------------------------------------------------
    // Result classes
    // -----------------------------------------------------------------------
    static class MethodEntry {
        long entryAddr;
        String name;
        int flags;
        long methPtr;
        long docPtr;

        MethodEntry(long addr, String name, int flags, long methPtr, long docPtr) {
            this.entryAddr = addr;
            this.name = name;
            this.flags = flags;
            this.methPtr = methPtr;
            this.docPtr = docPtr;
        }
    }

    static class TableResult {
        long tableAddr;
        List<MethodEntry> entries;
        boolean hasSentinel;

        TableResult(long addr, List<MethodEntry> entries, boolean hasSentinel) {
            this.tableAddr = addr;
            this.entries = entries;
            this.hasSentinel = hasSentinel;
        }
    }

    // -----------------------------------------------------------------------
    // Memory reading helpers
    // -----------------------------------------------------------------------

    private Address makeAddr(long offset) {
        return defaultSpace.getAddress(offset & 0xFFFFFFFFL);
    }

    private long readU32(long offset) throws Exception {
        byte[] buf = new byte[4];
        memory.getBytes(makeAddr(offset), buf);
        return ((buf[0] & 0xFFL))
             | ((buf[1] & 0xFFL) << 8)
             | ((buf[2] & 0xFFL) << 16)
             | ((buf[3] & 0xFFL) << 24);
    }

    private long readU32Safe(long offset) {
        try {
            return readU32(offset);
        } catch (Exception e) {
            return -1;
        }
    }

    private boolean isExecutable(long offset) {
        for (long[] r : exeRanges) {
            if (offset >= r[0] && offset <= r[1]) return true;
        }
        return false;
    }

    private boolean isReadable(long offset) {
        for (long[] r : initRanges) {
            if (offset >= r[0] && offset <= r[1]) return true;
        }
        return false;
    }

    /**
     * Reads a null-terminated C string. Returns null if invalid.
     */
    private String readCString(long offset, int maxLen) {
        if (!isReadable(offset)) return null;
        try {
            byte[] buf = new byte[maxLen];
            memory.getBytes(makeAddr(offset), buf);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < buf.length; i++) {
                int ch = buf[i] & 0xFF;
                if (ch == 0) {
                    return sb.length() > 0 ? sb.toString() : null;
                }
                if (ch >= 0x20 && ch < 0x7F) {
                    sb.append((char) ch);
                } else if (ch == '\t' || ch == '\n' || ch == '\r') {
                    sb.append((char) ch);
                } else {
                    return null; // non-ASCII byte
                }
            }
            return null; // no null terminator found
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Checks whether the offset points to a valid Python identifier.
     */
    private boolean isValidName(long offset) {
        String s = readCString(offset, MAX_NAME_LEN);
        if (s == null || s.isEmpty()) return false;
        char first = s.charAt(0);
        if (first != '_' && !Character.isLetter(first)) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_' && c != '.') return false;
        }
        return true;
    }

    /**
     * Checks whether the offset points to a valid doc-string (or is NULL=0).
     */
    private boolean isValidDoc(long offset) {
        if (offset == 0) return true;
        String s = readCString(offset, MAX_DOC_LEN);
        return s != null && !s.isEmpty();
    }

    // -----------------------------------------------------------------------
    // Flags -> human-readable string
    // -----------------------------------------------------------------------
    private String flagStr(int flags) {
        List<String> parts = new ArrayList<>();
        if ((flags & METH_VARARGS)  != 0) parts.add("VARARGS");
        if ((flags & METH_KEYWORDS) != 0) parts.add("KEYWORDS");
        if ((flags & METH_NOARGS)   != 0) parts.add("NOARGS");
        if ((flags & METH_O)        != 0) parts.add("O");
        if ((flags & METH_CLASS)    != 0) parts.add("CLASS");
        if ((flags & METH_STATIC)   != 0) parts.add("STATIC");
        if ((flags & METH_COEXIST)  != 0) parts.add("COEXIST");
        return parts.isEmpty() ? "0" : String.join("|", parts);
    }

    // -----------------------------------------------------------------------
    // Single entry validation
    // -----------------------------------------------------------------------
    private MethodEntry validateEntry(long offset) {
        long mlName  = readU32Safe(offset);
        long mlMeth  = readU32Safe(offset + 4);
        long mlFlags = readU32Safe(offset + 8);
        long mlDoc   = readU32Safe(offset + 12);

        if (mlName < 0 || mlMeth < 0 || mlFlags < 0 || mlDoc < 0) return null;

        // ml_name -> must point to a valid identifier
        if (!isValidName(mlName)) return null;

        // ml_meth -> must point to executable memory, non-NULL
        if (mlMeth == 0 || !isExecutable(mlMeth)) return null;

        // ml_flags -> no bits outside the valid mask
        int flags = (int)(mlFlags & 0xFFFFFFFFL);
        if ((flags & ~ALL_VALID_FLAGS) != 0) return null;

        // calling-convention combination must be valid
        int ccBits = flags & 0x0F;
        if (!VALID_CC.contains(ccBits)) return null;

        // ml_doc -> NULL or readable string
        if (!isValidDoc(mlDoc)) return null;

        String name = readCString(mlName, MAX_NAME_LEN);
        if (name == null) return null;

        return new MethodEntry(offset, name, flags, mlMeth, mlDoc);
    }

    private boolean isSentinel(long offset) {
        long val = readU32Safe(offset);
        return val == 0;
    }

    // -----------------------------------------------------------------------
    // Build memory ranges
    // -----------------------------------------------------------------------
    private void buildRanges() {
        exeRanges = new ArrayList<>();
        initRanges = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            long s = block.getStart().getOffset();
            long e = block.getEnd().getOffset();
            if (block.isExecute()) {
                exeRanges.add(new long[]{s, e});
            }
            if (block.isInitialized()) {
                initRanges.add(new long[]{s, e});
            }
        }
    }

    // -----------------------------------------------------------------------
    // Main scan
    // -----------------------------------------------------------------------
    private List<TableResult> scanForTables() throws Exception {
        List<TableResult> found = new ArrayList<>();
        Set<Long> visited = new HashSet<>();

        long totalBytes = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized()) totalBytes += block.getSize();
        }

        monitor.setMessage("Scanning for PyMethodDef tables...");
        monitor.setMaximum(totalBytes);
        long progress = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;

            long blockStart = block.getStart().getOffset();
            long blockSize  = block.getSize();
            long blockEnd   = blockStart + blockSize;

            // 4-byte alignment
            long off = blockStart;
            if (off % 4 != 0) off += 4 - (off % 4);

            long scanLimit = blockEnd - ENTRY_SIZE;

            while (off <= scanLimit) {
                if (monitor.isCancelled()) return found;

                long localProgress = off - blockStart;
                if (localProgress % 0x10000 == 0) {
                    monitor.setProgress(progress + localProgress);
                }

                if (visited.contains(off)) {
                    off += 4;
                    continue;
                }

                MethodEntry first = validateEntry(off);
                if (first == null) {
                    off += 4;
                    continue;
                }

                // Potential table start: read consecutive entries
                List<MethodEntry> entries = new ArrayList<>();
                long scanOff = off;

                while (scanOff + ENTRY_SIZE <= blockEnd) {
                    if (isSentinel(scanOff)) break;

                    MethodEntry me = validateEntry(scanOff);
                    if (me == null) break;

                    entries.add(me);
                    visited.add(scanOff);
                    scanOff += ENTRY_SIZE;
                }

                if (entries.size() >= MIN_TABLE_ENTRIES) {
                    boolean hasSentinel = isSentinel(scanOff);
                    if (hasSentinel) visited.add(scanOff);
                    found.add(new TableResult(off, entries, hasSentinel));
                    off = scanOff + (hasSentinel ? ENTRY_SIZE : 0);
                    continue;
                }

                off += 4;
            }

            progress += blockSize;
        }

        return found;
    }

    // -----------------------------------------------------------------------
    // Create PyMethodDef type in the DataTypeManager
    // -----------------------------------------------------------------------
    private DataType createPyMethodDefType() {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        DataType existing = dtm.getDataType("/PyMethodDef");
        if (existing != null) return existing;

        StructureDataType st = new StructureDataType("PyMethodDef", 0);
        st.add(PointerDataType.dataType, 4, "ml_name", "Method name (const char*)");
        st.add(PointerDataType.dataType, 4, "ml_meth", "C function pointer (PyCFunction)");
        st.add(IntegerDataType.dataType, 4, "ml_flags", "METH_* flags");
        st.add(PointerDataType.dataType, 4, "ml_doc", "Docstring (const char*)");

        return dtm.addDataType(st, null);
    }

    // -----------------------------------------------------------------------
    // Annotate table in the listing
    // -----------------------------------------------------------------------
    private void annotateTable(TableResult table, DataType structType) {
        Listing listing = currentProgram.getListing();
        SymbolTable symTable = currentProgram.getSymbolTable();

        int count = table.entries.size();
        int total = count + (table.hasSentinel ? 1 : 0);

        String baseName = table.entries.get(0).name;
        String label = String.format("PyMethodDef_table_%s_%d", baseName, count);

        Address tableAddr = makeAddr(table.tableAddr);

        // Clear existing code units in the area
        try {
            Address endAddr = makeAddr(table.tableAddr + (long) total * ENTRY_SIZE - 1);
            listing.clearCodeUnits(tableAddr, endAddr, false);
        } catch (Exception e) {
            // ignore
        }

        // Apply struct array
        try {
            ArrayDataType arrType = new ArrayDataType(structType, total, ENTRY_SIZE);
            listing.createData(tableAddr, arrType);
        } catch (Exception e) {
            // Fallback: apply individual structs
            for (int i = 0; i < total; i++) {
                try {
                    Address ea = makeAddr(table.tableAddr + (long) i * ENTRY_SIZE);
                    listing.createData(ea, structType);
                } catch (Exception e2) {
                    // ignore
                }
            }
        }

        // Label
        try {
            symTable.createLabel(tableAddr, label, SourceType.ANALYSIS);
        } catch (Exception e) {
            // ignore
        }

        // EOL comments for each entry (using getCodeUnitAt to avoid deprecated API)
        for (MethodEntry me : table.entries) {
            try {
                Address ea = makeAddr(me.entryAddr);
                CodeUnit cu = listing.getCodeUnitAt(ea);
                if (cu != null) {
                    String comment = String.format("PyMethodDef: %s  flags=%s (0x%X)",
                            me.name, flagStr(me.flags), me.flags);
                    cu.setComment(CodeUnit.EOL_COMMENT, comment);
                }
            } catch (Exception e) {
                // ignore
            }
        }

        // Sentinel comment
        if (table.hasSentinel) {
            try {
                Address sentAddr = makeAddr(table.tableAddr + (long) count * ENTRY_SIZE);
                CodeUnit cu = listing.getCodeUnitAt(sentAddr);
                if (cu != null) {
                    cu.setComment(CodeUnit.EOL_COMMENT, "PyMethodDef sentinel (NULL terminator)");
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // -----------------------------------------------------------------------
    // run() - entry point
    // -----------------------------------------------------------------------
    @Override
    protected void run() throws Exception {

        memory = currentProgram.getMemory();
        defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Verify 32-bit architecture
        int ptrSize = currentProgram.getLanguage().getDefaultSpace().getPointerSize();
        if (ptrSize != 4) {
            boolean cont = askYesNo("Warning",
                    "The binary appears to be " + (ptrSize * 8) + "-bit.\n"
                  + "This script is designed for 32-bit.\nContinue anyway?");
            if (!cont) return;
        }

        println("========================================================================");
        println("  FindPYMEthods - PyMethodDef Table Scanner");
        println("  Target: Python 2.7, 32-bit");
        println("========================================================================");
        println("");

        buildRanges();

        println("[*] Executable memory blocks:");
        for (long[] r : exeRanges) {
            println(String.format("      0x%08X - 0x%08X", r[0], r[1]));
        }
        println("");
        println("[*] Starting scan...");
        println("");

        List<TableResult> tables = scanForTables();

        if (tables.isEmpty()) {
            println("[!] No PyMethodDef tables found.");
            println("    Suggestions:");
            println("    - Verify the binary contains Python 2.7 code");
            println("    - Try lowering MIN_TABLE_ENTRIES to 1");
            println("    - Check that memory is properly mapped");
            return;
        }

        println(String.format("[+] Found %d PyMethodDef tables!%n", tables.size()));

        DataType structType = createPyMethodDefType();

        int idx = 1;
        int totalMethods = 0;
        for (TableResult table : tables) {
            println("------------------------------------------------------------");
            println(String.format("Table #%d @ 0x%08X  (%d methods%s)",
                    idx, table.tableAddr, table.entries.size(),
                    table.hasSentinel ? ", with sentinel" : ", NO sentinel"));
            println("------------------------------------------------------------");

            for (MethodEntry me : table.entries) {
                String docPreview = "";
                if (me.docPtr != 0) {
                    String ds = readCString(me.docPtr, 80);
                    if (ds != null) {
                        if (ds.length() > 60) ds = ds.substring(0, 60) + "...";
                        docPreview = "  doc=\"" + ds + "\"";
                    }
                }
                println(String.format("  0x%08X  %-30s  meth=0x%08X  flags=%-20s%s",
                        me.entryAddr, me.name, me.methPtr, flagStr(me.flags), docPreview));
            }

            annotateTable(table, structType);
            totalMethods += table.entries.size();
            idx++;
            println("");
        }

        println("========================================================================");
        println("  SUMMARY");
        println("========================================================================");
        println(String.format("  Tables found:      %d", tables.size()));
        println(String.format("  Total methods:     %d", totalMethods));
        println("");
        println("  PyMethodDef structure added to the Data Type Manager.");
        println("  Labels and comments applied to the Listing.");
        println("");
        println("  Tip: search for XREFs to the tables to find");
        println("  calls to Py_InitModule / Py_InitModule4.");
        println("========================================================================");
    }
}
