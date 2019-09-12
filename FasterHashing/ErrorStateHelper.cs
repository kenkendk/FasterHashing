using System;
namespace FasterHashing
{
    /// <summary>
    /// Internal helper class to avoid spamming the output with the same warnings
    /// </summary>    
    internal static class ErrorStateHelper
    {
        /// <summary>
        /// A value indicating if the offset issue has been reported
        /// </summary>
        public static bool HasReportedOffsetIssue { get; set; }
    }
}
