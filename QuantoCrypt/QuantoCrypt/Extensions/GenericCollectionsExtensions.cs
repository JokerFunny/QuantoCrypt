namespace System.Collections.Generic
{
    /// <summary>
    /// Extensions for the <see cref="System.Collections.Generic"/>.
    /// </summary>
    internal static class GenericCollectionsExtensions
    {
        /// <summary>
        /// Get the index of the element that is matchs target <paramref name="predicate"/>.
        /// </summary>
        /// <typeparam name="T">Target type.</typeparam>
        /// <param name="this">Target <see cref="IReadOnlyList{T}"/>.</param>
        /// <param name="predicate">Target <see cref="Func{T, bool}"/> to check for.</param>
        /// <returns>
        ///     Index of the target element in <paramref name="this"/> if matchs, otherwise - [-1].
        /// </returns>
        public static int IndexOf<T>(this IReadOnlyList<T> @this, Func<T, bool> predicate)
        {
            for (int i = 0; i < @this.Count; i++)
            {
                if (predicate(@this[i]))
                    return i;
            }

            return -1;
        }
    }
}
