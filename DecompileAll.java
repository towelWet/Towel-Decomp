// File: C:/Users/Towel/Downloads/toweldecomp/DecompileAll.java
// Decompiles all functions in the current program.
// Usage (headless): 
//   -postScript DecompileAll.java <outputFile>

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.util.task.TaskMonitor;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: -postScript DecompileAll.java <outputFile>");
            return;
        }
        String outputPath = args[0];
        File outputFile = new File(outputPath);
        println("Decompiling to: " + outputFile.getAbsolutePath());
        
        // Configure decompiler.
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        decompiler.setSimplificationStyle("decompile");
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        
        // Gather all functions.
        Listing listing = currentProgram.getListing();
        List<Function> allFunctions = new ArrayList<>();
        for (Function f : listing.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            allFunctions.add(f);
        }
        println("Total functions found: " + allFunctions.size());
        
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write("// Decompiled from: " + currentProgram.getName() + "\n");
            writer.write("// Total functions: " + allFunctions.size() + "\n");
            writer.write("// Timestamp: " + new java.util.Date() + "\n\n");
            
            int count = 0;
            for (Function function : allFunctions) {
                if (monitor.isCancelled()) {
                    println("Cancelled by user.");
                    break;
                }
                monitor.setMessage("Decompiling " + function.getName());
                monitor.incrementProgress(1);
                count++;
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (results != null && results.decompileCompleted()) {
                    writer.write("// Function: " + function.getName() + "\n");
                    writer.write("// Address: " + function.getEntryPoint() + "\n");
                    writer.write(results.getDecompiledFunction().getC() + "\n");
                    writer.write("// =====================================\n\n");
                    println("Decompiled: " + function.getName());
                } else {
                    writer.write("// Failed to decompile: " + function.getName() + "\n");
                    if (results != null) {
                        writer.write("// Error: " + results.getErrorMessage() + "\n\n");
                    }
                    println("Failed to decompile: " + function.getName());
                }
            }
            writer.write("\n// Decompilation completed at: " + new java.util.Date() + "\n");
            println("Decompilation completed. Total functions processed: " + count);
        } catch (IOException e) {
            println("Error writing output file: " + e.getMessage());
            e.printStackTrace();
        } finally {
            decompiler.closeProgram();
            decompiler.dispose();
        }
    }
}
