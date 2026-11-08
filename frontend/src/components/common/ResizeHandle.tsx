import React, { forwardRef } from "react";
import { Separator, SeparatorProps } from "react-resizable-panels";

export interface ResizeHandleProps extends SeparatorProps {
  orientation?: "horizontal" | "vertical";
}

export const ResizeHandle = forwardRef<HTMLDivElement, ResizeHandleProps>(
  ({ orientation = "horizontal", className = "", ...props }, ref) => {
    const isHorizontalGroup = orientation === "horizontal";

    return (
      <Separator
        elementRef={ref}
        className={`group relative flex items-center justify-center transition-colors select-none z-10 ${
          isHorizontalGroup
            ? "w-[3px] hover:w-[4px] cursor-col-resize hover:bg-cyan-500/80 active:bg-cyan-400 bg-[#1e293b]/80"
            : "h-[3px] hover:h-[4px] cursor-row-resize hover:bg-cyan-500/80 active:bg-cyan-400 bg-[#1e293b]/80"
        } ${className}`}
        {...props}
      >
        <div
          className={`rounded-full transition-all duration-150 pointer-events-none ${
            isHorizontalGroup
              ? "w-0.5 h-8 bg-transparent group-hover:bg-cyan-300 group-active:bg-cyan-200"
              : "h-0.5 w-8 bg-transparent group-hover:bg-cyan-300 group-active:bg-cyan-200"
          }`}
        />
      </Separator>
    );
  }
);

ResizeHandle.displayName = "Separator";
