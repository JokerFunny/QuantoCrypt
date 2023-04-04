namespace QuantoCrypt.Infrastructure.KEM
{
    /// <summary>
    /// Represents result of Encaps() operation.
    /// </summary>
    public interface ISecretWithEncapsulation : IDisposable
    {
        ///<summary>
        /// Return the session key associated with the encapsulation.
        /// </summary>
        /// <returns>Session key.</returns>
        byte[] GetSecret();

        /// <summary>
        /// Return the data that carries the session key in its encapsulated form.
        /// </summary>
        /// <returns>Encapsulated value of the session key.</returns>
        byte[] GetEncapsulation();
    }
}
